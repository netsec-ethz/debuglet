// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && roles_integration

package roles

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/demo"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/pelletier/go-toml/v2"
)

const soakLifetime = 120 * time.Second

// TestInstalledScheduleSoak measures a declared small TEST profile through its
// actual finite TESLA lifetime. Exhaustion is a refusal, not automatic rotation.
func TestInstalledScheduleSoak(t *testing.T) {
	root, evidence := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT"), os.Getenv("DEBUGLET_SOAK_EVIDENCE_DIR")
	if !filepath.IsAbs(root) || !filepath.IsAbs(evidence) {
		t.Fatal("absolute installed package and soak evidence directories are required")
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatalf("installed source identity: %v", err)
	}
	work, err := os.MkdirTemp(evidence, "state-")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := os.OpenFile(filepath.Join(evidence, "observations.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	var children []*demo.Child
	var logs []*os.File
	var listeners []net.Listener
	var targets sync.WaitGroup
	started := time.Now()
	completed, reconciled := 0, 0
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			listener.Close()
		}
		targets.Wait()
		joined := true
		for i := len(children) - 1; i >= 0; i-- {
			phase, stop := context.WithTimeout(context.Background(), 10*time.Second)
			if err := children[i].Stop(phase); err != nil {
				t.Error("daemon stop:", err)
			}
			stop()
			joined = joined && children[i].CleanupComplete()
		}
		for _, log := range logs {
			if err := log.Close(); err != nil {
				t.Error(err)
			}
		}
		if !joined {
			t.Error("owned daemon groups did not join")
		}
		if !t.Failed() && joined {
			if err := os.RemoveAll(work); err != nil {
				t.Error(err)
			}
		}
		result := map[string]any{"event": "result", "passed": !t.Failed(), "joined": joined, "completed": completed,
			"reconciled_expired_runs": reconciled, "elapsed_seconds": time.Since(started).Seconds()}
		if err := json.NewEncoder(journal).Encode(result); err != nil {
			t.Error(err)
		}
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	emit := func(value any) {
		t.Helper()
		if err := json.NewEncoder(journal).Encode(value); err != nil {
			t.Fatal(err)
		}
	}
	emit(map[string]any{"event": "configuration", "source": assets.Manifest.SourceSHA, "version": assets.Manifest.Version,
		"executors": 2, "max_debuglets_per_executor": 4, "maximum_jobs": 122, "epoch_seconds": 1,
		"chain_length": 120, "schedule_lifetime_seconds": 120, "max_start_delay_seconds": 3,
		"max_completion_seconds": 8, "max_rss_bytes": 512 << 20, "max_rss_growth_bytes": 128 << 20,
		"max_fds": 128, "max_fd_growth": 32, "max_storage_bytes": 256 << 20, "packet_counter": "fallback"})
	launch := func(name, executable string, role storagecheck.Role, config any) readiness.Record {
		t.Helper()
		emit(map[string]any{"event": "daemon_configuration", "name": name, "config": config})
		dir := filepath.Join(work, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := demo.BootstrapFresh(ctx, role, filepath.Join(dir, "state.sqlite")); err != nil {
			t.Fatal(err)
		}
		data, err := toml.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		log, err := os.OpenFile(filepath.Join(dir, "daemon.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		logs = append(logs, log)
		ready := filepath.Join(dir, "ready.json")
		child, err := demo.StartChild(demo.ChildSpec{Path: executable, Dir: dir, Env: isolatedEnvironment(dir),
			Args: []string{"-config", path, "-ready-file", ready}, Stdout: log, Stderr: log})
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, child)
		phase, stop := context.WithTimeout(ctx, 20*time.Second)
		defer stop()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			data, err := readRegular(ready, 4096)
			if err == nil {
				var record readiness.Record
				if err := decode(data, &record); err != nil || record.PID != child.PID() {
					t.Fatal("invalid daemon readiness", err)
				}
				return record
			}
			if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			select {
			case <-phase.Done():
				t.Fatal("daemon readiness:", phase.Err())
			case <-child.Done():
				t.Fatal("daemon exited before readiness")
			case <-tick.C:
			}
		}
	}
	dbPath := filepath.Join(work, "dispatcher", "state.sqlite")
	d := launch("dispatcher", assets.Dispatcher, storagecheck.Dispatcher, dispatcherconfig.DispatcherConfig{
		Server: dispatcherconfig.ServerConfig{BindHost: "127.0.0.1", LocalDevelopment: true, Version: assets.Manifest.Version},
		TLS:    dispatcherconfig.TLSConfig{Disable: true}, Sui: dispatcherconfig.SuiConfig{Disabled: true},
		Scheduler: dispatcherconfig.SchedulerConfig{ExecutorTimeout: 10, SchedulerGranularityMs: 100},
		Database:  dispatcherconfig.DatabaseConfig{Path: dbPath}, Logging: dispatcherconfig.LoggingConfig{LogLevel: "info", JSONLogs: true}})
	c := sdk(t, "http://"+d.HTTPAddr)
	ids := []string{uuid.NewString(), uuid.NewString()}
	for i, id := range ids {
		name := fmt.Sprintf("executor-%d", i)
		local := true
		launch(name, assets.Executor, storagecheck.Executor, executorconfig.ExecutorConfig{
			Identity:   executorconfig.IdentityConfig{ExecutorID: id, Version: assets.Manifest.Version},
			Dispatcher: executorconfig.DispatcherConfig{Addr: d.GRPCAddr, YamuxAddr: d.HTTPAddr}, TLS: executorconfig.TLSConfig{Disable: true},
			Resources: executorconfig.ResourcesConfig{Capacity: 1_000_000, MaxDebuglets: 4}, Tesla: executorconfig.TeslaConfig{Delay: 1, ChainLength: 120},
			Network:  executorconfig.NetworkConfig{PacketCounter: "fallback", DisableSCIONEnvironment: true, Policy: executorconfig.PolicyConfig{LocalTargets: &local}},
			Database: executorconfig.DatabaseConfig{Path: filepath.Join(work, name, "state.sqlite")},
			Logging:  executorconfig.LoggingConfig{LogLevel: "info", JSONLogs: true}, Pricing: executorconfig.PricingConfig{Currency: "TEST", PricePerBwS: 1}})
	}
	nodes, err := c.Nodes(ctx)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("two ready executors: %v %v", nodes, err)
	}
	var firstExpiry, lastExpiry time.Time
	for _, node := range nodes {
		if (node.ID != ids[0] && node.ID != ids[1]) || !node.Ready || node.TeslaDelaySec != 1 || node.TeslaAnchorTimestampNs <= 0 {
			t.Fatal("unexpected schedule", node)
		}
		expiry := time.Unix(0, node.TeslaAnchorTimestampNs).Add(soakLifetime)
		if firstExpiry.IsZero() || expiry.Before(firstExpiry) {
			firstExpiry = expiry
		}
		if expiry.After(lastExpiry) {
			lastExpiry = expiry
		}
		emit(map[string]any{"event": "schedule", "executor": node.ID, "anchor_ns": node.TeslaAnchorTimestampNs, "expiry": expiry})
	}
	type exchange struct {
		nonce    string
		accepted time.Time
		err      error
	}
	expected := []chan string{make(chan string, 1), make(chan string, 1)}
	results := []chan exchange{make(chan exchange, 1), make(chan exchange, 1)}
	for i := range ids {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		targets.Add(1)
		go func(i int, listener net.Listener) {
			defer targets.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				accepted := time.Now()
				var nonce string
				select {
				case nonce = <-expected[i]:
				case <-ctx.Done():
					conn.Close()
					return
				}
				err = conn.SetDeadline(time.Now().Add(4 * time.Second))
				if err == nil {
					_, err = io.WriteString(conn, "DEBUGLET/1 "+nonce+"\n")
				}
				if err == nil {
					var line string
					line, err = bufio.NewReader(io.LimitReader(conn, 128)).ReadString('\n')
					if err == nil && line != "ACK "+nonce+"\n" {
						err = errors.New("incorrect target ACK")
					}
				}
				conn.Close()
				select {
				case results[i] <- exchange{nonce, accepted, err}:
				case <-ctx.Done():
					return
				}
			}
		}(i, listener)
	}
	wasm, err := os.ReadFile(filepath.Join(root, "share/debuglet/demo.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	batch := func(start int64) (*client.PreparedBatch, []string) {
		nonces := []string{strings.ReplaceAll(uuid.NewString(), "-", ""), strings.ReplaceAll(uuid.NewString(), "-", "")}
		requests := make([]client.Request, 2)
		for i, id := range ids {
			requests[i] = client.Request{OrderID: int64(i), ExecutorID: id, StartTimestamp: &start, Wasm: wasm,
				Args: []string{listeners[i].Addr().String(), nonces[i]}, Policy: client.Policy{FloorBW: 64_000, CeilBW: 64_000, TimeoutMS: 4000, Addresses: []string{"127.0.0.1"}}}
		}
		prepared, err := client.Prepare(requests)
		if err != nil {
			t.Fatal(err)
		}
		return prepared, nonces
	}
	type resource struct {
		PID int   `json:"pid"`
		RSS int64 `json:"rss_bytes"`
		FDs int   `json:"fds"`
	}
	var baseline []resource
	sample := func() {
		t.Helper()
		values := make([]resource, len(children))
		for i, child := range children {
			select {
			case <-child.Done():
				t.Fatal("daemon exited during soak")
			default:
			}
			path := fmt.Sprintf("/proc/%d", child.PID())
			data, err := readRegular(path+"/smaps_rollup", 32<<10)
			if err != nil {
				t.Fatal(err)
			}
			var rss int64
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 3 && fields[0] == "Rss:" {
					rss, err = strconv.ParseInt(fields[1], 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					rss *= 1024
				}
			}
			fds, err := os.ReadDir(path + "/fd")
			if err != nil {
				t.Fatal(err)
			}
			values[i] = resource{child.PID(), rss, len(fds)}
		}
		var storage int64
		if err := filepath.WalkDir(work, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type().IsRegular() {
				info, err := entry.Info()
				if err != nil {
					return err
				}
				storage += info.Size()
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		emit(map[string]any{"event": "resources", "elapsed_seconds": time.Since(started).Seconds(), "processes": values, "storage_bytes": storage})
		for i, value := range values {
			if value.RSS <= 0 || value.RSS > 512<<20 || value.FDs > 128 {
				t.Fatalf("resource bound exceeded: %+v", value)
			}
			if baseline != nil && (value.RSS-baseline[i].RSS > 128<<20 || value.FDs-baseline[i].FDs > 32) {
				t.Fatalf("resource growth exceeded: before=%+v after=%+v", baseline[i], value)
			}
		}
		if storage > 256<<20 {
			t.Fatal("storage bound exceeded", storage)
		}
		if baseline == nil && completed >= 8 {
			baseline = values
		}
	}
	loadStart := time.Now()
	for completed < 120 && time.Now().Add(8*time.Second).Before(firstExpiry) {
		start := time.Now().Unix() + 2
		prepared, nonces := batch(start)
		for i := range ids {
			expected[i] <- nonces[i]
		}
		submitted := time.Now()
		receipt, err := c.SubmitTEST(ctx, prepared)
		if err != nil {
			emit(map[string]any{"event": "unexpected_submission_failure", "error": err.Error()})
			t.Fatal(err)
		}
		for i, id := range receipt.IDs {
			phase, done := context.WithTimeout(ctx, 8*time.Second)
			var outcome exchange
			select {
			case outcome = <-results[i]:
			case <-phase.Done():
				done()
				t.Fatal("target did not complete", phase.Err())
			}
			done()
			delay := outcome.accepted.Sub(time.Unix(start, 0))
			if outcome.err != nil || outcome.nonce != nonces[i] || delay < 0 || delay > 3*time.Second {
				t.Fatalf("target/start delay: %+v %s", outcome, delay)
			}
			awaitOutput(t, ctx, c, id, "DEBUGLET_DEMO_OK "+nonces[i]+"\n")
			elapsed := time.Since(submitted)
			if elapsed > 8*time.Second {
				t.Fatal("completion bound exceeded", elapsed)
			}
			completed++
			emit(map[string]any{"event": "completed", "id": id, "executor": ids[i], "nonce": nonces[i], "start_delay_seconds": delay.Seconds(), "completion_seconds": elapsed.Seconds()})
		}
		sample()
	}
	if completed < 40 || time.Since(loadStart) < 60*time.Second {
		t.Fatal("insufficient sustained workload", completed, time.Since(loadStart))
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for time.Now().Before(lastExpiry.Add(2 * time.Second)) {
		sample()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
	prepared, nonces := batch(time.Now().Unix())
	for i := range ids {
		expected[i] <- nonces[i]
	}
	_, err = c.SubmitTEST(ctx, prepared)
	var submission *client.SubmissionError
	if !errors.As(err, &submission) || submission.TransactionID == "" {
		t.Fatal("expired executor did not refuse a recorded TEST batch", err)
	}
	emit(map[string]any{"event": "expired_submission", "transaction": submission.TransactionID, "client_outcome_unknown": submission.OutcomeUnknown, "error": err.Error()})
	// Reconcile the failed upload through the owned database; no client retry
	// creates a new transaction or masks an unknown result.
	db, err := sqlitedb.Open(dbPath, sqlitedb.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, "SELECT uuid FROM debuglets WHERE transaction_id = ? ORDER BY order_id", submission.TransactionID)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	var expiredIDs []string
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Error(err)
			break
		}
		expiredIDs = append(expiredIDs, id.String())
	}
	err = errors.Join(rows.Err(), rows.Close(), db.Close())
	if err != nil {
		t.Fatal(err)
	}
	if len(expiredIDs) != 2 {
		t.Fatal("expired batch has unresolved run identities", expiredIDs)
	}
	for _, id := range expiredIDs {
		state, err := c.Status(ctx, id)
		if err != nil || state.State != client.StateExited || state.Error == "" {
			t.Fatalf("unreconciled expired run %s: %+v %v", id, state, err)
		}
		reconciled++
	}
	for i := range ids {
		data, err := os.ReadFile(filepath.Join(work, fmt.Sprintf("executor-%d", i), "daemon.log"))
		if err != nil || !strings.Contains(string(data), "TESLA key chain exhausted") {
			t.Fatalf("executor %d did not report actual expiry: %v", i, err)
		}
	}
	for time.Now().Before(lastExpiry.Add(10 * time.Second)) {
		sample()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
	for i := range ids {
		select {
		case result := <-results[i]:
			t.Fatalf("unexpected post-load target exchange: %+v", result)
		default:
		}
	}
	if time.Since(started) <= soakLifetime {
		t.Fatal("workload did not cross the complete schedule interval")
	}
}
