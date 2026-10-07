//go:build linux && roles_integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package roles

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/demo"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/pelletier/go-toml/v2"
)

type installedLaunch func(string, string, storagecheck.Role, any) readiness.Record

func installedRendezvous(t *testing.T) (context.Context, demo.Assets, string, installedLaunch) {
	t.Helper()
	root, evidence := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT"), os.Getenv("DEBUGLET_ROLE_EVIDENCE_DIR")
	if !filepath.IsAbs(root) || !filepath.IsAbs(evidence) {
		t.Fatal("absolute installed and evidence directories required")
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatalf("installed source identity: %v", err)
	}
	work, err := os.MkdirTemp(evidence, "rendezvous-")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	var children []*demo.Child
	var logs []*os.File
	t.Cleanup(func() {
		clean := true
		for i := len(children) - 1; i >= 0; i-- {
			stop, done := context.WithTimeout(context.Background(), 10*time.Second)
			err := children[i].Stop(stop)
			done()
			if err != nil {
				clean = false
				t.Error("owned daemon cleanup:", err)
			}
		}
		for _, log := range logs {
			log.Close()
		}
		if clean && !t.Failed() {
			os.RemoveAll(work)
		} else {
			t.Log("preserved owned fixture:", work)
		}
	})
	launch := func(name, executable string, role storagecheck.Role, config any) readiness.Record {
		t.Helper()
		dir := filepath.Join(work, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := storagecheck.BootstrapFresh(ctx, role, filepath.Join(dir, "state.sqlite")); err != nil {
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
		child, err := demo.StartChild(demo.ChildSpec{Path: executable, Dir: dir, Env: isolatedEnvironment(dir), Args: []string{"-config", path, "-ready-file", ready}, Stdout: log, Stderr: log})
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, child)
		phase, done := context.WithTimeout(ctx, 20*time.Second)
		defer done()
		for {
			data, err := readRegular(ready, 4096)
			if err == nil {
				var record readiness.Record
				if decode(data, &record) != nil || record.PID != child.PID() {
					t.Fatal("invalid readiness")
				}
				return record
			}
			if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			select {
			case <-phase.Done():
				t.Fatal("readiness:", phase.Err())
			case <-child.Done():
				t.Fatal("daemon exited")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	return ctx, assets, work, launch
}

// TestInstalledRendezvous runs the installed command and exact packaged guest
// across two real executor processes. Every listener and target is loopback.
func TestInstalledRendezvous(t *testing.T) {
	ctx, assets, work, launch := installedRendezvous(t)
	d := launch("dispatcher", assets.Dispatcher, storagecheck.Dispatcher, dispatcherconfig.DispatcherConfig{
		Admission:   dispatcherconfig.DefaultAdmissionConfig(),
		Attribution: dispatcherconfig.DefaultAttributionConfig(),
		Server:      dispatcherconfig.ServerConfig{BindHost: "127.0.0.1", LocalDevelopment: true, Version: assets.Manifest.Version}, TLS: dispatcherconfig.TLSConfig{Disable: true}, Sui: dispatcherconfig.SuiConfig{Disabled: true}, Scheduler: dispatcherconfig.SchedulerConfig{ExecutorTimeout: 10, SchedulerGranularityMs: 100}, Output: dispatcherconfig.DefaultOutputConfig(), Database: dispatcherconfig.DatabaseConfig{Path: filepath.Join(work, "dispatcher", "state.sqlite")}, Logging: dispatcherconfig.LoggingConfig{LogLevel: "info", JSONLogs: true},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ids := []string{uuid.NewString(), uuid.NewString()}
	for i, id := range ids {
		name := fmt.Sprintf("executor-%d", i)
		local := true
		network := executorconfig.NetworkConfig{PacketCounter: "fallback", DisableSCIONEnvironment: true, Policy: executorconfig.PolicyConfig{LocalTargets: &local}}
		if i == 0 {
			network.PublicHost = "127.0.0.1"
			network.PublicPorts = strconv.Itoa(port)
		}
		launch(name, assets.Executor, storagecheck.Executor, executorconfig.ExecutorConfig{Identity: executorconfig.IdentityConfig{ExecutorID: id, Version: assets.Manifest.Version}, Dispatcher: executorconfig.DispatcherConfig{Addr: d.GRPCAddr, YamuxAddr: d.HTTPAddr}, TLS: executorconfig.TLSConfig{Disable: true}, Resources: executorconfig.ResourcesConfig{Capacity: 1_000_000, MaxDebuglets: 4}, Tesla: executorconfig.TeslaConfig{Delay: 1, ChainLength: 300}, Network: network, Database: executorconfig.DatabaseConfig{Path: filepath.Join(work, name, "state.sqlite")}, Logging: executorconfig.LoggingConfig{LogLevel: "info", JSONLogs: true}, Pricing: executorconfig.PricingConfig{Currency: "TEST", PricePerBwS: 1}})
	}
	c := sdk(t, "http://"+d.HTTPAddr)
	for {
		nodes, err := c.Nodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ready := 0
		for _, node := range nodes {
			if node.Ready {
				ready++
			}
		}
		if ready == 2 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	command := exec.CommandContext(ctx, assets.CLI, "--endpoint", "http://"+d.HTTPAddr, "--config", filepath.Join(work, "client.json"), "--output", "json", "rendezvous", "--server-executor", ids[0], "--client-executor", ids[1], "--server-allow", "127.0.0.1", "--duration", "40s")
	command.Env = isolatedEnvironment(work)
	var output, diagnostic bytes.Buffer
	command.Stdout = &output
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		t.Fatalf("installed pair: %v; %s; %s", err, diagnostic.String(), output.String())
	}
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	witnessed := map[string]bool{}
	outputIDs := map[string]string{}
	var result client.RendezvousResult
	for scanner.Scan() {
		var page struct {
			Role   string         `json:"role"`
			RunID  string         `json:"run_id"`
			Output client.LogPage `json:"output"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.Role != "" {
			if !validID(page.RunID) || outputIDs[page.Role] != "" && outputIDs[page.Role] != page.RunID {
				t.Fatal("output identity changed")
			}
			outputIDs[page.Role] = page.RunID
			for _, entry := range page.Output.Logs {
				if bytes.Contains(entry.Output, []byte("DEBUGLET_ECHO_OK")) {
					witnessed[page.Role] = true
				}
			}
		} else if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !witnessed["server"] || !witnessed["client"] || result.Server.Cleanup != "confirmed_absent" || result.Client.Cleanup != "confirmed_absent" || result.Server.ID == result.Client.ID {
		t.Fatalf("incomplete pair witness: %+v %v", result, witnessed)
	}
	if outputIDs["server"] != result.Server.ID || outputIDs["client"] != result.Client.ID || result.Endpoint != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
		t.Fatal("structured endpoint or output did not match the owned runs")
	}
	for _, run := range []client.RendezvousRun{result.Server, result.Client} {
		detail, err := c.RunDetail(ctx, run.ID)
		if err != nil || detail.Execution == nil || detail.Execution.StartedObservedAt == nil || detail.Execution.TerminalObservedAt == nil || detail.Outcome.State != client.StateExited {
			t.Fatalf("retained observations: %+v %v", detail.Execution, err)
		}
	}
	t.Logf("server=%s client=%s endpoint=%s cleanup=confirmed_absent for both runs", result.Server.ID, result.Client.ID, result.Endpoint)
}
