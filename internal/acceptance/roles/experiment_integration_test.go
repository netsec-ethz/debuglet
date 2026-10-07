//go:build linux && roles_integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package roles

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// TestInstalledExperiment runs the same coordinated guest in five independent
// executor processes and checks the retained output of every admitted run.
func TestInstalledExperiment(t *testing.T) {
	ctx, assets, work, launch := installedRendezvous(t)
	wasm, err := os.ReadFile(os.Getenv("DEBUGLET_EXPERIMENT_WASM"))
	if err != nil {
		t.Fatal(err)
	}
	d := launch("dispatcher", assets.Dispatcher, storagecheck.Dispatcher, dispatcherconfig.DispatcherConfig{
		Admission: dispatcherconfig.DefaultAdmissionConfig(), Attribution: dispatcherconfig.DefaultAttributionConfig(),
		Server: dispatcherconfig.ServerConfig{BindHost: "127.0.0.1", LocalDevelopment: true, Version: assets.Manifest.Version},
		TLS:    dispatcherconfig.TLSConfig{Disable: true}, Sui: dispatcherconfig.SuiConfig{Disabled: true},
		Scheduler: dispatcherconfig.SchedulerConfig{ExecutorTimeout: 10, SchedulerGranularityMs: 100}, Output: dispatcherconfig.DefaultOutputConfig(),
		Database: dispatcherconfig.DatabaseConfig{Path: filepath.Join(work, "dispatcher", "state.sqlite")}, Logging: dispatcherconfig.LoggingConfig{LogLevel: "info", JSONLogs: true},
	})
	c := sdk(t, "http://"+d.HTTPAddr)
	requests := make([]client.Request, 5)
	for i := range requests {
		id, name := uuid.NewString(), fmt.Sprintf("executor-%d", i)
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := conn.LocalAddr().(*net.UDPAddr).Port
		conn.Close()
		local := true
		launch(name, assets.Executor, storagecheck.Executor, executorconfig.ExecutorConfig{
			Identity:   executorconfig.IdentityConfig{ExecutorID: id, Version: assets.Manifest.Version},
			Dispatcher: executorconfig.DispatcherConfig{Addr: d.GRPCAddr, YamuxAddr: d.HTTPAddr}, TLS: executorconfig.TLSConfig{Disable: true},
			Resources: executorconfig.ResourcesConfig{Capacity: 1_000_000, MaxDebuglets: 4}, Tesla: executorconfig.TeslaConfig{Delay: 1, ChainLength: 300},
			Network:  executorconfig.NetworkConfig{PublicHost: "127.0.0.1", PublicPorts: strconv.Itoa(port), PacketCounter: "fallback", DisableSCIONEnvironment: true, Policy: executorconfig.PolicyConfig{LocalTargets: &local}},
			Database: executorconfig.DatabaseConfig{Path: filepath.Join(work, name, "state.sqlite")}, Logging: executorconfig.LoggingConfig{LogLevel: "info", JSONLogs: true}, Pricing: executorconfig.PricingConfig{Currency: "TEST", PricePerBwS: 1},
		})
		requests[i] = client.Request{OrderID: int64(i), ExecutorID: id, Wasm: wasm, Args: []string{strconv.Itoa(i)}, Policy: client.Policy{FloorBW: 100_000, CeilBW: 200_000, TimeoutMS: 30_000, Addresses: []string{"127.0.0.1"}, ListenUDP: true}}
	}
	for {
		nodes, err := c.Nodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ready := 0
		for _, n := range nodes {
			if n.Ready {
				ready++
			}
		}
		if ready == len(requests) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	batch, err := client.Prepare(requests)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := c.SubmitTEST(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	var sharedStart int64
	for _, id := range submission.IDs {
		var output []byte
		var after int64
		for {
			page, err := c.Logs(ctx, id, client.LogOptions{After: after, Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range page.Logs {
				output = append(output, entry.Output...)
			}
			after = page.After
			if page.Error != "" {
				t.Fatalf("participant %s: %s output=%s", id, page.Error, output)
			}
			if len(output) > 64<<10 {
				t.Fatal("excessive guest output")
			}
			if page.Output.State == "truncated" {
				t.Fatalf("participant %s output truncated: %+v", id, page.Output)
			}
			if page.State == client.StateExited && !page.HasMore && page.Output.State == "complete" {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatalf("waiting %s: %v output=%s", id, ctx.Err(), output)
			case <-time.After(50 * time.Millisecond):
			}
		}
		var result struct {
			ExperimentID string `json:"experiment_id"`
			StartTimeNS  int64  `json:"start_time_ns"`
			Sent         int    `json:"sent"`
			Received     int    `json:"received"`
		}
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("participant %s output=%s: %v", id, output, err)
		}
		if result.ExperimentID != submission.TransactionID || result.StartTimeNS == 0 || result.Sent != 4 || result.Received != 4 {
			t.Fatalf("participant %s: %+v", id, result)
		}
		if sharedStart != 0 && sharedStart != result.StartTimeNS {
			t.Fatal("participants received different start times")
		}
		sharedStart = result.StartTimeNS
		t.Logf("run=%s group=%s start=%d sent=%d received=%d", id, result.ExperimentID, result.StartTimeNS, result.Sent, result.Received)
	}
}
