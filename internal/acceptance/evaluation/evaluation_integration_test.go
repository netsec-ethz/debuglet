// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && evaluation_integration

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestControlledNetworkEvaluation(t *testing.T) {
	if os.Getenv("DEBUGLET_EVALUATION_ISOLATED") != "1" {
		t.Fatal("run through the isolated evaluation lane")
	}
	root, evidence, native, guest := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT"), os.Getenv("DEBUGLET_EVALUATION_EVIDENCE_DIR"), os.Getenv("DEBUGLET_EVALUATION_NATIVE"), os.Getenv("DEBUGLET_EVALUATION_WASM")
	for _, path := range []string{root, evidence, native, guest} {
		if !filepath.IsAbs(path) {
			t.Fatal("absolute installed, evidence and probe paths required")
		}
	}
	for _, module := range []string{"sch_htb", "sch_netem", "cls_u32"} {
		if _, err := os.Stat("/sys/module/" + module); err != nil {
			t.Fatalf("unsupported kernel: %s is not already available; no module is loaded by this fixture", module)
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("evaluation requires an isolated loopback-only namespace", interfaces, err)
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin/dbl"))
	if err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatal("installed source mismatch", err)
	}
	wasm, err := os.ReadFile(guest)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(wasm)
	inputs := experiment{Version: 1, SourceSHA: assets.Manifest.SourceSHA, WorkloadSHA256: hex.EncodeToString(hash[:]), Conditions: conditions, Trials: []trial{}}
	write := func(name string, value any) {
		t.Helper()
		data, err := json.MarshalIndent(value, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(evidence, name), append(data, '\n'), 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	write("experiment.json", inputs)
	state, err := os.MkdirTemp(evidence, "state-")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	var roles []chan error
	ownedQdisc := false
	var target *net.UDPConn
	var targetDone chan struct{}
	tc, err := exec.LookPath("tc")
	if err != nil {
		t.Fatal("unsupported tools image: missing tc", err)
	}
	command := func(path string, args ...string) []byte {
		t.Helper()
		file, err := os.CreateTemp(state, "command-*.log")
		if err != nil {
			t.Fatal(err)
		}
		child, err := demo.StartChild(demo.ChildSpec{Path: path, Dir: state, Args: args, Env: []string{"LANG=C", "LC_ALL=C", "TZ=UTC", "TMPDIR=" + state}, Stdout: file, Stderr: file})
		if err == nil {
			phase, stop := context.WithTimeout(ctx, 35*time.Second)
			err = child.Wait(phase)
			stop()
			cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
			err = errors.Join(err, child.Stop(cleanup))
			done()
			if !child.CleanupComplete() {
				err = errors.Join(err, errors.New("command process group did not join"))
			}
		}
		err = errors.Join(err, file.Close())
		data, readErr := os.ReadFile(file.Name())
		err = errors.Join(err, readErr)
		if err != nil {
			t.Fatalf("command %s %v: %v: %s", path, args, err, data)
		}
		return data
	}
	t.Cleanup(func() {
		cancel()
		if target != nil {
			target.Close()
			if targetDone != nil {
				<-targetDone
			}
		}
		joined := true
		for i := len(roles) - 1; i >= 0; i-- {
			select {
			case err := <-roles[i]:
				if err != nil {
					joined = false
					t.Error("role join:", err)
				}
			case <-time.After(15 * time.Second):
				joined = false
				t.Error("role did not join")
			}
		}
		if ownedQdisc {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			data, err := exec.CommandContext(cleanup, tc, "qdisc", "del", "dev", "lo", "root").CombinedOutput()
			stop()
			if err != nil {
				joined = false
				t.Error("owned qdisc cleanup:", err, string(data))
			}
		}
		if joined && !t.Failed() {
			if err := os.RemoveAll(state); err != nil {
				t.Error(err)
			}
		}
		data, _ := json.Marshal(map[string]any{"passed": !t.Failed(), "joined": joined, "trials": len(inputs.Trials)})
		if err := os.WriteFile(filepath.Join(evidence, "cleanup.json"), append(data, '\n'), 0600); err != nil {
			t.Error(err)
		}
	})
	before := command(tc, "-j", "qdisc", "show", "dev", "lo")
	var initial []struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(before, &initial); err != nil || len(initial) != 1 || initial[0].Kind != "noqueue" {
		t.Fatal("refusing to replace an existing loopback qdisc", string(before), err)
	}
	write("tools.json", map[string]any{"tc": string(command(tc, "-V")), "image": os.Getenv("DEBUGLET_CI_JOB_IMAGE"), "image_id": os.Getenv("DEBUGLET_CI_IMAGE_ID"), "loopback_before": json.RawMessage(before)})
	startRole := func(name string, start func(context.Context, demo.Assets, demo.RoleOptions) error, profile connections.Profile) demo.RoleEnvironment {
		t.Helper()
		ready := make(chan demo.RoleEnvironment, 1)
		done := make(chan error, 1)
		roles = append(roles, done)
		options := demo.RoleOptions{Name: name, StateDir: filepath.Join(state, name), Dispatcher: profile, Ready: func(value demo.RoleEnvironment) error { ready <- value; return nil }}
		go func() { done <- start(ctx, assets, options) }()
		select {
		case value := <-ready:
			return value
		case err := <-done:
			done <- err
			t.Fatal("role startup:", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		return demo.RoleEnvironment{}
	}
	dispatcher := startRole("dispatcher", demo.DispatcherUp, connections.Profile{})
	executor := startRole("executor", demo.ExecutorUp, connections.Profile{Endpoint: dispatcher.Endpoint})
	api, err := client.New(dispatcher.Endpoint, client.Options{RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		nodes, err := api.Nodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) == 1 && nodes[0].ID == executor.ExecutorID && nodes[0].Ready {
			break
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	target, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	inputs.Target = target.LocalAddr().String()
	write("experiment.json", inputs)
	targetDone = make(chan struct{})
	var targetMu sync.Mutex
	var events []targetEvent
	var targetErr error
	go func() {
		defer close(targetDone)
		buffer := make([]byte, 1025)
		for {
			n, peer, err := target.ReadFromUDP(buffer)
			received := time.Now()
			if err != nil {
				return
			}
			if n != 1024 {
				targetErr = errors.New("target received malformed payload")
				return
			}
			sent := time.Now()
			event := targetEvent{hex.EncodeToString(buffer[:16]), buffer[16] == 1, binary.BigEndian.Uint32(buffer[17:21]), received.UnixNano(), sent.UnixNano(), sent.Sub(received).Nanoseconds()}
			if _, err := target.WriteToUDP(buffer[:n], peer); err != nil {
				targetErr = err
				return
			}
			targetMu.Lock()
			events = append(events, event)
			targetMu.Unlock()
		}
	}()
	port := strconv.Itoa(target.LocalAddr().(*net.UDPAddr).Port)
	command(tc, "qdisc", "add", "dev", "lo", "root", "handle", "1:", "htb", "default", "1")
	ownedQdisc = true
	for _, class := range []string{"1:1", "1:2"} {
		command(tc, "class", "add", "dev", "lo", "parent", "1:", "classid", class, "htb", "rate", "10gbit", "ceil", "10gbit", "quantum", "60000")
	}
	for _, direction := range []string{"dport", "sport"} {
		command(tc, "filter", "add", "dev", "lo", "protocol", "ip", "parent", "1:", "prio", "1", "u32", "match", "ip", "protocol", "17", "0xff", "match", "ip", direction, port, "0xffff", "flowid", "1:2")
	}
	filters := command(tc, "-j", "filter", "show", "dev", "lo", "parent", "1:")
	if err := os.WriteFile(filepath.Join(evidence, "filters.json"), filters, 0600); err != nil {
		t.Fatal(err)
	}
	for conditionIndex, setup := range conditions {
		if conditionIndex > 0 {
			// Replacing netem preserves some omitted options, including rate.
			// Recreate only the owned leaf; control traffic keeps its class.
			command(tc, "qdisc", "del", "dev", "lo", "parent", "1:2", "handle", "20:")
		}
		for repeat := 0; repeat < 3; repeat++ {
			kinds := []string{"native", "wasm"}
			if repeat%2 == 1 {
				kinds = []string{"wasm", "native"}
			}
			for _, kind := range kinds {
				args := []string{"qdisc", "replace", "dev", "lo", "parent", "1:2", "handle", "20:", "netem", "limit", "512"}
				if setup.DelayMS > 0 {
					args = append(args, "delay", fmt.Sprintf("%dms", setup.DelayMS))
				}
				if setup.LossPercent > 0 {
					args = append(args, "loss", fmt.Sprintf("%d%%", setup.LossPercent))
				}
				if setup.RateBPS > 0 {
					args = append(args, "rate", fmt.Sprintf("%dbit", setup.RateBPS))
				}
				command(tc, args...)
				base := fmt.Sprintf("%s-%d-%s", setup.Name, repeat, kind)
				write(base+"-qdisc-before.json", json.RawMessage(command(tc, "-s", "-j", "qdisc", "show", "dev", "lo")))
				identity := uuid.New()
				nonce := hex.EncodeToString(identity[:])
				arguments := []string{target.LocalAddr().String(), nonce, setup.Mode}
				started := time.Now()
				var filename string
				if kind == "native" {
					filename = base + ".json"
					if err := os.WriteFile(filepath.Join(evidence, filename), command(native, arguments...), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					prepared, err := client.Prepare([]client.Request{{OrderID: 0, ExecutorID: executor.ExecutorID, Wasm: wasm, Args: arguments, Policy: client.Policy{FloorBW: 1_000_000, CeilBW: 1_000_000_000, TimeoutMS: 25_000, Addresses: []string{"127.0.0.1"}}}})
					if err != nil {
						t.Fatal(err)
					}
					submitted, err := api.SubmitTEST(ctx, prepared)
					if err != nil {
						t.Fatal(err)
					}
					phase, stop := context.WithTimeout(ctx, 35*time.Second)
					var exported client.Result
					for {
						exported, err = api.Export(phase, submitted.IDs[0])
						if err != nil {
							stop()
							t.Fatal(err)
						}
						if exported.Outcome.State == client.StateExited {
							if exported.Outcome.Error != "" {
								stop()
								t.Fatal("probe failed", exported.Outcome.Error)
							}
							if exported.Output.Status.State == "complete" {
								break
							}
							if exported.Output.Status.State == "truncated" {
								stop()
								t.Fatal("probe output truncated")
							}
						}
						select {
						case <-tick.C:
						case <-phase.Done():
							stop()
							t.Fatal("probe did not reach complete output", phase.Err())
						}
					}
					stop()
					filename = base + "-result.json"
					write(filename, exported)
				}
				inputs.Trials = append(inputs.Trials, trial{setup.Name, repeat, kind, nonce, filename, time.Since(started).Nanoseconds()})
				write("experiment.json", inputs)
				write(base+"-qdisc-after.json", json.RawMessage(command(tc, "-s", "-j", "qdisc", "show", "dev", "lo")))
				targetMu.Lock()
				snapshot := append([]targetEvent(nil), events...)
				targetMu.Unlock()
				write("target-events.json", snapshot)
			}
		}
	}
	target.Close()
	<-targetDone
	target = nil
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	result, err := analyze(evidence)
	if err != nil {
		t.Fatal(err)
	}
	write("summary.json", result)
}
