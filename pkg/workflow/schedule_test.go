// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func periodicWorkflow() Workflow {
	return Workflow{Version: 1, Name: "Periodic observations", Entry: "clock", Nodes: []Node{
		{ID: "clock", Block: "every", Inputs: map[string]any{"interval_ms": float64(1000), "duration_ms": float64(50), "start_delay_ms": float64(0)}},
		{ID: "out", Block: "emit", Inputs: map[string]any{"name": "iteration"}},
	}, Edges: []Edge{edge("control", "clock", "body", "out", "in"), edge("data", "clock", "iteration", "out", "value")}}
}

func TestEveryGenerationAndScope(t *testing.T) {
	w := periodicWorkflow()
	p, err := Generate(w)
	if err != nil || !strings.Contains(p.Source, "runtime.Every") || !strings.Contains(p.Source, "runtime.Forget(\"out\")") {
		t.Fatalf("%v %s", err, p.Source)
	}
	for name, change := range map[string]func(*Workflow){
		"too long": func(w *Workflow) { w.Nodes[0].Inputs["duration_ms"] = float64(86400001) },
		"nested": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "repeat", Block: "repeat", Inputs: map[string]any{"count": float64(2)}})
			w.Entry = "repeat"
			w.Edges = append(w.Edges, edge("control", "repeat", "body", "clock", "in"))
		},
		"escape": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "after", Block: "emit", Inputs: map[string]any{"name": "last"}})
			w.Edges = append(w.Edges, edge("control", "clock", "done", "after", "in"), edge("data", "clock", "iteration", "after", "value"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := periodicWorkflow()
			change(&w)
			if len(Validate(w)) == 0 {
				t.Fatal("invalid periodic graph accepted")
			}
		})
	}
}

func TestGeneratedEveryRunsWASI(t *testing.T) {
	outputs, counts := executeReportWorkflow(t, periodicWorkflow())
	if outputs["out"]["value"] != float64(1) || counts["emit"] != 1 {
		t.Fatalf("%v %v", outputs, counts)
	}
}

// Real nanosleep is important here: WASI's default fake clock hides a host call
// that cannot be cancelled until a multi-hour sleep finishes.
func TestScheduledWASICancelsDuringHostSleep(t *testing.T) {
	if testing.Short() {
		t.Skip("generated WASI compilation")
	}
	w := periodicWorkflow()
	w.Nodes[0].Inputs = map[string]any{"interval_ms": float64(2000), "duration_ms": float64(3000), "start_delay_ms": float64(0), "immediate": false}
	w.Nodes = append(w.Nodes, Node{ID: "started", Block: "emit", Inputs: map[string]any{"name": "ready", "value": true}})
	w.Entry = "started"
	w.Edges = append(w.Edges, edge("control", "started", "next", "clock", "in"))
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "main.go"), filepath.Join(dir, "schedule.wasm")
	if err := os.WriteFile(source, []byte(p.Source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, source)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOOS=wasip1", "GOARCH=wasm")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	wasm, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer r.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		t.Fatal(err)
	}
	compiled, err := r.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	run, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		_, err := r.InstantiateModule(run, compiled, wazero.NewModuleConfig().WithSysWalltime().WithSysNanotime().WithSysNanosleep().WithStdout(scheduleSignalWriter{ready}))
		done <- err
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("before scheduling: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("guest did not start")
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	cancelRun()
	select {
	case err := <-done:
		if err == nil || time.Since(start) > time.Second {
			t.Fatalf("cancellation took %v: %v", time.Since(start), err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("guest remained inside host sleep")
	}
}

type scheduleSignalWriter struct{ ready chan struct{} }

func (w scheduleSignalWriter) Write(p []byte) (int, error) {
	select {
	case w.ready <- struct{}{}:
	default:
	}
	return len(p), nil
}

func TestVisualMeshBoundsAndHostRequirements(t *testing.T) {
	e := Experiment{Version: 1, Kind: "experiment", Name: "Mesh"}
	for i := 0; i < 16; i++ {
		e.Participants = append(e.Participants, Participant{ID: fmt.Sprintf("node%d", i), Workflow: Workflow{Version: 1, Name: "UDP", Entry: "start", Nodes: []Node{{ID: "start", Block: "udp_probe_start"}}}})
	}
	_, p, err := GenerateParticipant(e, "node0")
	if err != nil || !p.RequireUDPListener || !strings.Contains(strings.Join(p.RequiredHostFunctions, ","), "debuglet_io_v1.mesh_start") {
		t.Fatalf("metadata=%+v err=%v", p, err)
	}
	if !strings.Contains(p.Source, "experiment.Close()") || !strings.Contains(p.Source, "SetScheduleAnchor") {
		t.Fatal("missing service lifecycle")
	}
	e.Participants = append(e.Participants, Participant{ID: "too_many", Workflow: e.Participants[0].Workflow})
	if len(ValidateExperiment(e)) == 0 {
		t.Fatal("17 participants accepted")
	}
	w := Workflow{Version: 1, Name: "Listener conflict", Entry: "start", Nodes: []Node{{ID: "start", Block: "tcp_responder_start"}, {ID: "message", Block: "await_message", Inputs: map[string]any{"source": "peer", "channel": "x"}}}}
	if ds := Validate(w); len(ds) == 0 {
		t.Fatal("TCP responder and message receiver share listener")
	}
}

// Capability metadata must match compiled imports, not only generated source:
// linking an unused service operation would reject otherwise legacy executors.
func TestGeneratedMeshCapabilityImports(t *testing.T) {
	if testing.Short() {
		t.Skip("generated WASI compilation")
	}
	for _, kind := range []string{"legacy", "udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			w := Workflow{Version: 1, Name: kind, Entry: "first", Nodes: []Node{{ID: "first", Block: "emit", Inputs: map[string]any{"name": "ready", "value": true}}}}
			if kind != "legacy" {
				start, middle, stop := "udp_probe_start", "udp_probe_snapshot", "udp_probe_stop"
				if kind == "tcp" {
					start, middle, stop = "tcp_responder_start", "tcp_transfer", "tcp_responder_stop"
				}
				w.Nodes = []Node{{ID: "first", Block: start}, {ID: "read", Block: middle}, {ID: "stop", Block: stop}}
				w.Edges = []Edge{edge("control", "first", "next", "read", "in"), edge("control", "read", "next", "stop", "in"), edge("data", "first", "service", "stop", "service")}
				if kind == "udp" {
					w.Edges = append(w.Edges, edge("data", "first", "service", "read", "service"))
				} else {
					w.Nodes[1].Inputs = map[string]any{"peer": "b"}
				}
			}
			e := Experiment{Version: 1, Kind: "experiment", Name: kind, Participants: []Participant{{ID: "a", Workflow: w}, {ID: "b", Workflow: w}}}
			_, p, err := GenerateParticipant(e, "a")
			if err != nil {
				t.Fatal(err)
			}
			if kind == "legacy" && strings.Contains(p.Source, "experiment.Close()") {
				t.Fatal("legacy experiment linked service cleanup")
			}
			dir := t.TempDir()
			source, binary := filepath.Join(dir, "main.go"), filepath.Join(dir, "imports.wasm")
			if err := os.WriteFile(source, []byte(p.Source), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, source)
			cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOOS=wasip1", "GOARCH=wasm")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build: %v %s", err, output)
			}
			wasm, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			r := wazero.NewRuntime(ctx)
			defer r.Close(ctx)
			module, err := r.CompileModule(ctx, wasm)
			if err != nil {
				t.Fatal(err)
			}
			actual, declared := []string{}, []string{}
			for _, function := range module.ImportedFunctions() {
				namespace, name, _ := function.Import()
				if namespace == "debuglet_io_v1" && strings.HasPrefix(name, "mesh_") {
					actual = append(actual, namespace+"."+name)
				}
			}
			for _, name := range p.RequiredHostFunctions {
				if strings.HasPrefix(name, "debuglet_io_v1.mesh_") {
					declared = append(declared, name)
				}
			}
			slices.Sort(actual)
			slices.Sort(declared)
			if !reflect.DeepEqual(actual, declared) {
				t.Fatalf("actual imports %v; declared %v", actual, declared)
			}
		})
	}
}
