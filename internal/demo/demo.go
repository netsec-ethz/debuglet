package demo

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/pelletier/go-toml/v2"
)

const (
	diagnosticLimit  = 1 << 20
	guestOutputLimit = 64 << 10
	readyLimit       = 4 << 10
	pollEvery        = 50 * time.Millisecond
	cleanupTimeout   = 5 * time.Second
)

type childProcess interface {
	PID() int
	Done() <-chan struct{}
	Wait(context.Context) error
	Stop(context.Context) error
	CleanupComplete() bool
}

// dependencies is private so the CLI has no fault-injection switches. The
// acceptance harness uses the same Run path with real children and an observer.
type dependencies struct {
	resolveAssets func(string) (Assets, error)
	bootstrap     func(context.Context, SchemaRole, string) error
	checkSchema   func(context.Context, SchemaRole, string) error
	startChild    func(ChildSpec) (childProcess, error)
	startTarget   func(context.Context, string) (targetProcess, error)
	observe       func(context.Context, observation) error
}

// verifySchema checks a database against the supported schema versions before
// a service is started on it.
func (d dependencies) verifySchema(ctx context.Context, role SchemaRole, path string) error {
	check := d.checkSchema
	if check == nil {
		check = CheckSchema
	}
	if err := check(ctx, role, path); err != nil {
		return fmt.Errorf("%s database: %w", role, err)
	}
	return nil
}

type observation struct {
	Dir, DispatcherDB, ExecutorDB, Endpoint, ExecutorID, Nonce string
	DispatcherPID, ExecutorPID                                 int
	Submission                                                 client.Submission
	Result                                                     Result
}

func productionDependencies() dependencies {
	return dependencies{
		resolveAssets: ResolveAssets,
		bootstrap:     BootstrapFresh,
		checkSchema:   CheckSchema,
		startChild:    func(spec ChildSpec) (childProcess, error) { return StartChild(spec) },
		startTarget:   startTarget,
	}
}

// Run verifies the installed assets, runs one wallet-free local measurement,
// and joins all owned processes and callbacks before reporting success.
func Run(ctx context.Context, assets Assets) (Result, error) {
	return run(ctx, assets, productionDependencies())
}

func run(ctx context.Context, assets Assets, deps dependencies) (result Result, err error) {
	if runtime.GOOS != "linux" {
		return result, errors.New("installed demo requires Linux")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// Resolve again at the library boundary: callers cannot substitute an
	// unverified daemon or guest by constructing Assets manually.
	assets, err = deps.resolveAssets(assets.CLI)
	if err != nil {
		return result, fmt.Errorf("verify installed demo: %w", err)
	}
	guest, err := readRegularFile(assets.Guest, 24<<20)
	if err != nil || len(guest) == 0 {
		return result, errors.Join(errors.New("read installed demo guest"), err)
	}
	dir, err := os.MkdirTemp("", "debuglet-demo-")
	if err != nil {
		return result, fmt.Errorf("create demo state: %w", err)
	}
	workCtx, cancelWork := context.WithCancelCause(ctx)
	watchCtx, cancelWatches := context.WithCancel(workCtx)
	var watchers sync.WaitGroup
	var dispatcherChild, executorChild childProcess
	var target targetProcess
	var dispatcherLog, executorLog *boundedLog

	defer func() {
		for _, item := range []struct {
			name  string
			child childProcess
		}{{"dispatcher", dispatcherChild}, {"executor", executorChild}} {
			if item.child != nil && isDone(item.child.Done()) {
				err = errors.Join(err, fmt.Errorf("%s exited before demo cleanup", item.name))
			}
		}
		cancelWatches()
		watchers.Wait()
		if workCtx.Err() != nil {
			err = errors.Join(err, context.Cause(workCtx))
		}
		cancelWork(nil)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		var cleanupErr error
		if target != nil {
			phase, end := cleanupPhase(cleanupCtx, 3)
			cleanupErr = errors.Join(cleanupErr, target.Stop(phase))
			end()
		}
		for index, item := range []struct {
			name  string
			child childProcess
		}{{"executor", executorChild}, {"dispatcher", dispatcherChild}} {
			if item.child != nil {
				phase, end := cleanupPhase(cleanupCtx, 2-index)
				if e := item.child.Stop(phase); e != nil {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("stop %s: %w", item.name, e))
				}
				end()
			}
		}
		// Direct-child reaping does not prove that descendants or the stop
		// controller finished. Join the complete existing stop operation within
		// the original deadline before deciding whether state can be removed.
		for _, child := range []childProcess{executorChild, dispatcherChild} {
			if child != nil && !child.CleanupComplete() {
				cleanupErr = errors.Join(cleanupErr, child.Stop(cleanupCtx))
			}
		}
		if target != nil && !isDone(target.Done()) {
			cleanupErr = errors.Join(cleanupErr, target.Stop(cleanupCtx))
		}
		allJoined := (target == nil || isDone(target.Done())) &&
			(dispatcherChild == nil || dispatcherChild.CleanupComplete()) &&
			(executorChild == nil || executorChild.CleanupComplete())
		for _, item := range []struct {
			name string
			log  *boundedLog
		}{{"dispatcher", dispatcherLog}, {"executor", executorLog}} {
			if item.log != nil {
				cleanupErr = errors.Join(cleanupErr, item.log.Close())
				if err != nil || cleanupErr != nil {
					if data := item.log.Bytes(); len(data) > 0 {
						err = errors.Join(err, fmt.Errorf("%s diagnostics:\n%s", item.name, data))
					}
				}
			}
		}
		if allJoined {
			cleanupErr = errors.Join(cleanupErr, os.RemoveAll(dir))
		} else {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("demo cleanup incomplete; retained owned state at %s", dir))
		}
		err = errors.Join(err, cleanupErr, ctx.Err())
		if err == nil {
			result.Cleanup = "complete"
		}
	}()
	if err := os.Chmod(dir, 0700); err != nil {
		return result, err
	}
	dispatcherDB := filepath.Join(dir, "dispatcher.sqlite")
	executorDB := filepath.Join(dir, "executor.sqlite")
	if err := deps.bootstrap(workCtx, DispatcherSchema, dispatcherDB); err != nil {
		return result, fmt.Errorf("bootstrap dispatcher: %w", err)
	}
	if err := deps.bootstrap(workCtx, ExecutorSchema, executorDB); err != nil {
		return result, fmt.Errorf("bootstrap executor: %w", err)
	}
	nonce, err := randomHex()
	if err != nil {
		return result, err
	}
	executorID, err := randomUUID()
	if err != nil {
		return result, err
	}
	target, err = deps.startTarget(workCtx, nonce)
	if err != nil {
		return result, err
	}
	if err := validateAddress(target.Addr()); err != nil {
		return result, fmt.Errorf("invalid local target: %w", err)
	}
	dispatcherConfig := filepath.Join(dir, "dispatcher.toml")
	dispatcherReady := filepath.Join(dir, "dispatcher-ready.json")
	if err := writeConfig(dispatcherConfig, dispatcherConfiguration(assets.Manifest.Version, dispatcherDB)); err != nil {
		return result, err
	}
	dispatcherLog, err = newBoundedLog(filepath.Join(dir, "dispatcher.log"), cancelWork)
	if err != nil {
		return result, err
	}
	dispatcherChild, err = deps.startChild(ChildSpec{
		Path: assets.Dispatcher, Dir: dir,
		Args: []string{"--config", dispatcherConfig, "--ready-file", dispatcherReady},
		Env:  childEnvironment(dir), Stdout: dispatcherLog, Stderr: dispatcherLog,
	})
	if err != nil {
		return result, err
	}
	watchChild(watchCtx, &watchers, "dispatcher", dispatcherChild, cancelWork)
	dispatcherRecord, err := awaitReady(workCtx, dispatcherReady, dispatcherChild.PID(), "")
	if err != nil {
		return result, fmt.Errorf("dispatcher readiness: %w", err)
	}
	endpoint := "http://" + dispatcherRecord.HTTPAddr
	c, err := client.New(endpoint, client.Options{})
	if err != nil {
		return result, err
	}
	if err := awaitDiscovery(workCtx, c, ""); err != nil {
		return result, fmt.Errorf("dispatcher HTTP readiness: %w", err)
	}
	executorConfig := filepath.Join(dir, "executor.toml")
	executorReady := filepath.Join(dir, "executor-ready.json")
	if err := writeConfig(executorConfig, executorConfiguration(assets.Manifest.Version, executorID, executorDB, dispatcherRecord)); err != nil {
		return result, err
	}
	executorLog, err = newBoundedLog(filepath.Join(dir, "executor.log"), cancelWork)
	if err != nil {
		return result, err
	}
	executorChild, err = deps.startChild(ChildSpec{
		Path: assets.Executor, Dir: dir,
		Args: []string{"--config", executorConfig, "--ready-file", executorReady},
		Env:  childEnvironment(dir), Stdout: executorLog, Stderr: executorLog,
	})
	if err != nil {
		return result, err
	}
	watchChild(watchCtx, &watchers, "executor", executorChild, cancelWork)
	if _, err := awaitReady(workCtx, executorReady, executorChild.PID(), executorID); err != nil {
		return result, fmt.Errorf("executor readiness: %w", err)
	}
	if err := awaitDiscovery(workCtx, c, executorID); err != nil {
		return result, fmt.Errorf("executor discovery: %w", err)
	}
	batch, err := client.Prepare([]client.Request{{
		OrderID: 1, ExecutorID: executorID, Wasm: guest,
		Args:   []string{target.Addr(), nonce},
		Policy: client.Policy{FloorBW: 64_000, CeilBW: 1_000_000, TimeoutMS: 15_000, Addresses: []string{"127.0.0.1"}},
	}})
	if err != nil {
		return result, err
	}
	submission, err := c.SubmitTEST(workCtx, batch)
	if err != nil {
		return result, fmt.Errorf("submit local demo: %w", err)
	}
	result = Result{Version: assets.Manifest.Version, ExecutorID: executorID, RunID: submission.IDs[0]}
	if err := collectResult(workCtx, c, result.RunID, executorID, nonce, target); err != nil {
		return result, err
	}
	result.State = client.StateExited
	result.Response = "DEBUGLET/1 " + nonce
	if deps.observe != nil {
		if err := deps.observe(workCtx, observation{
			Dir: dir, DispatcherDB: dispatcherDB, ExecutorDB: executorDB, Endpoint: endpoint,
			ExecutorID: executorID, Nonce: nonce, DispatcherPID: dispatcherChild.PID(), ExecutorPID: executorChild.PID(),
			Submission: submission, Result: result,
		}); err != nil {
			return result, fmt.Errorf("demo acceptance observation: %w", err)
		}
	}
	return result, nil
}

// Divide only the remaining shared budget. No phase may extend cleanup, and
// one stuck owner cannot consume all the time reserved for later owners.
func cleanupPhase(ctx context.Context, owners int) (context.Context, context.CancelFunc) {
	deadline, _ := ctx.Deadline()
	remaining := time.Until(deadline)
	if remaining < 0 {
		remaining = 0
	}
	return context.WithDeadline(ctx, time.Now().Add(remaining/time.Duration(owners)))
}

func isDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func watchChild(ctx context.Context, wg *sync.WaitGroup, name string, child childProcess, cancel context.CancelCauseFunc) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
		case <-child.Done():
			if ctx.Err() == nil {
				cancel(fmt.Errorf("%s exited before demo cleanup: %w", name, errors.Join(errors.New("unexpected child exit"), child.Wait(ctx))))
			}
		}
	}()
}

func awaitReady(ctx context.Context, path string, pid int, executorID string) (readiness.Record, error) {
	for {
		if err := ctx.Err(); err != nil {
			return readiness.Record{}, context.Cause(ctx)
		}
		record, err := ReadReadyRecord(path, pid, executorID)
		if err == nil {
			return record, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return record, err
		}
		if err := waitPoll(ctx); err != nil {
			return readiness.Record{}, err
		}
	}
}

// ReadReadyRecord reads one published readiness record and checks it against
// the process that was supposed to publish it. The record is evidence that the
// daemon reached its own ready point: an existing process, or a service
// manager that merely created one, proves nothing on its own. A missing record
// is reported as os.ErrNotExist so a caller can keep waiting for it.
func ReadReadyRecord(path string, pid int, executorID string) (readiness.Record, error) {
	data, err := readRegularFile(path, readyLimit)
	if err != nil {
		return readiness.Record{}, err
	}
	var record readiness.Record
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&record); err != nil {
		return record, fmt.Errorf("invalid ready record: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return record, errors.New("trailing ready record data")
	}
	if record.SchemaVersion != 1 || record.PID != pid || pid <= 0 {
		return record, errors.New("ready record schema/PID does not match launched child")
	}
	if executorID == "" {
		if record.ExecutorID != "" {
			return record, errors.New("dispatcher ready record has executor identity")
		}
		if err := validateAddress(record.HTTPAddr); err != nil {
			return record, err
		}
		if err := validateAddress(record.GRPCAddr); err != nil {
			return record, err
		}
	} else if record.ExecutorID != executorID || record.HTTPAddr != "" || record.GRPCAddr != "" {
		return record, errors.New("executor ready record does not match launched identity")
	}
	return record, nil
}

func validateAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("ready address is not host:port")
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || p < 1 || p > 65535 {
		return errors.New("ready address must be a literal loopback IP with a nonzero port")
	}
	return nil
}

func awaitDiscovery(ctx context.Context, c *client.Client, executorID string) error {
	for {
		nodes, err := c.Nodes(ctx)
		if err == nil {
			if executorID == "" {
				return nil
			}
			for _, node := range nodes {
				if node.ID == executorID && node.Ready {
					return nil
				}
			}
		} else if ctx.Err() != nil {
			return context.Cause(ctx)
		} else {
			var networkError net.Error
			if !errors.As(err, &networkError) && !errors.Is(err, io.EOF) {
				return err
			}
		}
		if err := waitPoll(ctx); err != nil {
			return err
		}
	}
}

func collectResult(ctx context.Context, c *client.Client, id, executorID, nonce string, target targetProcess) error {
	var output []byte
	var cursor int64
	marker := []byte("DEBUGLET_DEMO_OK " + nonce + "\n")
	for {
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		if isDone(target.Done()) {
			if err := target.Wait(ctx); err != nil {
				return fmt.Errorf("local target exchange: %w", err)
			}
		}
		state, err := c.Status(ctx, id)
		if err != nil {
			return err
		}
		if state.ExecutorID != executorID {
			return errors.New("demo result belongs to a different executor")
		}
		if state.State == client.StateExited && state.Error != "" {
			return fmt.Errorf("demo workload failed: %s", state.Error)
		}
		page, err := c.Logs(ctx, id, client.LogOptions{After: cursor, Limit: 100})
		if err != nil {
			return err
		}
		for _, entry := range page.Logs {
			if len(entry.Output) > guestOutputLimit-len(output) {
				return errors.New("demo guest output exceeds 64 KiB")
			}
			output = append(output, entry.Output...)
		}
		cursor = page.After
		if page.State == client.StateExited && page.Error != "" {
			return fmt.Errorf("demo workload failed: %s", page.Error)
		}
		if state.State == client.StateExited && bytes.Contains(output, marker) && isDone(target.Done()) {
			if err := target.Wait(ctx); err != nil {
				return fmt.Errorf("local target exchange: %w", err)
			}
			return nil
		}
		// A terminal state is not a final output cursor. Keep collecting until
		// the matching marker appears, or the command's deadline expires.
		if !page.HasMore {
			if err := waitPoll(ctx); err != nil {
				return err
			}
		}
	}
}

func waitPoll(ctx context.Context) error {
	timer := time.NewTimer(pollEvery)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func randomHex() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("create demo nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("create executor identity: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// No inherited variables: these static Go daemons need neither a search PATH,
// credentials, proxies, HOME, nor SCION/Sui configuration. Temporary files stay
// in the invocation's owned directory; external SCION loading is disabled too.
func childEnvironment(dir string) []string {
	return []string{"TMPDIR=" + dir, "LANG=C", "LC_ALL=C", "TZ=UTC"}
}

func dispatcherConfiguration(version, db string) map[string]any {
	return map[string]any{
		// local_development is what makes the wallet-free flow usable without a
		// credential. It is written only here, where this package generates the
		// configuration of a loopback environment it owns end to end.
		"server":    map[string]any{"version": version, "bind_host": "127.0.0.1", "http_port": 0, "grpc_port": 0, "local_development": true, "behind_tls_terminator": false},
		"logging":   map[string]any{"log_level": "info", "json_logs": true},
		"scheduler": map[string]any{"executor_timeout": 60, "scheduler_granularity_ms": 100},
		"tls":       map[string]any{"disable": true, "cert_file": "", "key_file": "", "ca_file": ""},
		"database":  map[string]any{"path": db},
		"sui":       map[string]any{"disabled": true, "network": "", "grpc_endpoint": "", "graphql_url": "", "address": "", "payment_registry_id": "", "payment_kit_package": "", "keystore_path": ""},
	}
}

func executorConfiguration(version, id, db string, record readiness.Record) map[string]any {
	return map[string]any{
		"identity":   map[string]any{"executor_id": id, "version": version},
		"dispatcher": map[string]any{"addr": record.GRPCAddr, "yamux_addr": record.HTTPAddr},
		"tls":        map[string]any{"disable": true},
		"resources":  map[string]any{"capacity": int64(1_000_000_000), "max_debuglets": 4},
		"tesla":      map[string]any{"seed": "", "delay": 1, "chain_length": 0},
		"network": map[string]any{"interface": "", "packet_counter": "fallback", "disable_scion_environment": true, "public_host": "", "public_ports": "",
			// The local environment measures against a target on this machine,
			// so it says so; an executor that does not write this reaches no
			// loopback service.
			"policy": map[string]any{"local_targets": true}},
		"logging":     map[string]any{"log_level": "info", "json_logs": true},
		"credentials": map[string]any{"ca_cert": "", "client_cert": "", "client_key": ""},
		"database":    map[string]any{"path": db},
		"pricing":     map[string]any{"price_per_bw_s": 1, "currency": "TEST", "sui_wallet": "", "trial_price_limit": 0, "trial_time_limit": 0},
	}
}

func writeConfig(path string, config map[string]any) error {
	data, err := toml.Marshal(config)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	return errors.Join(writeErr, f.Close())
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file within the %d-byte limit", filepath.Base(path), limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", filepath.Base(path), limit)
	}
	return data, err
}

// boundedLog combines stdout/stderr in one total allowance and keeps draining
// after overflow so a pipe writer cannot deadlock process shutdown.
type boundedLog struct {
	mu      sync.Mutex
	file    *os.File
	data    []byte
	err     error
	onError context.CancelCauseFunc
}

func newBoundedLog(path string, onError context.CancelCauseFunc) (*boundedLog, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return &boundedLog{file: f, onError: onError}, nil
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	remaining := diagnosticLimit - len(b.data)
	n := len(p)
	if n > remaining {
		n = remaining
	}
	if n > 0 {
		b.data = append(b.data, p[:n]...)
		if _, err := b.file.Write(p[:n]); err != nil && b.err == nil {
			b.err = err
		}
	}
	if n < len(p) && b.err == nil {
		b.err = errors.New("demo child diagnostics exceed 1 MiB")
	}
	err := b.err
	b.mu.Unlock()
	if err != nil {
		b.onError(err)
	}
	return len(p), nil
}

func (b *boundedLog) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data)
}

func (b *boundedLog) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return errors.Join(b.err, b.file.Close())
}
