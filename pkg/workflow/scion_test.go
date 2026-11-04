// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
)

func TestSCIONRequirements(t *testing.T) {
	w := Workflow{Version: 1, Name: "SCION requirements", Entry: "paths", Nodes: []Node{
		{ID: "paths", Block: "scion_paths", Inputs: map[string]any{"address": "1-ff00:0:110,192.0.2.1:4000"}},
		{ID: "select", Block: "scion_select_path", Inputs: map[string]any{"address": "1-ff00:0:110,[2001:db8::1]:4000", "path_id": "path-a"}},
		{ID: "exchange", Block: "scion_udp_exchange", Inputs: map[string]any{"address": "1-ff00:0:110,192.0.2.1:4000", "path_id": "path-a"}},
		{ID: "listen", Block: "scion_listener_address"}, {ID: "receive", Block: "scion_receive"},
		{ID: "reply", Block: "scion_reply", Inputs: map[string]any{"sender": "1-ff00:0:111,192.0.2.2:4000"}},
	}}
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if !p.RequireSCION || !p.RequireSCIONListener || p.RequireUDPListener || p.RequireICMP {
		t.Fatalf("wrong requirements: %+v", p)
	}
	if !reflect.DeepEqual(p.Destinations, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatal(p.Destinations)
	}
	want := []string{"debuglet_io_v1.scion_exchange", "debuglet_io_v1.scion_listener_address", "debuglet_io_v1.scion_paths", "debuglet_io_v1.scion_receive", "debuglet_io_v1.scion_reply", "debuglet_io_v1.scion_select_path"}
	if !reflect.DeepEqual(p.RequiredHostFunctions, want) {
		t.Fatal(p.RequiredHostFunctions)
	}

	w = Workflow{Version: 1, Name: "Dynamic SCION endpoint", Entry: "paths", Nodes: []Node{
		{ID: "endpoint", Block: "constant", Inputs: map[string]any{"value": "1-ff00:0:110,192.0.2.3:4000"}},
		{ID: "paths", Block: "scion_paths"},
	}, Edges: []Edge{edge("data", "endpoint", "value", "paths", "address")}}
	p, err = Generate(w)
	if err != nil || !reflect.DeepEqual(p.Destinations, []string{"192.0.2.3"}) || p.RequireSCIONListener {
		t.Fatalf("constant endpoint: %+v %v", p, err)
	}
	w.Nodes[0] = Node{ID: "endpoint", Block: "concat", Inputs: map[string]any{"a": "1-ff00:0:110,", "b": "192.0.2.3:4000"}}
	p, err = Generate(w)
	if err != nil || len(p.Destinations) != 0 || !p.RequireSCION {
		t.Fatalf("dynamic endpoint must retain capability but not invent policy: %+v %v", p, err)
	}
	old, err := Generate(sampleWorkflow())
	if err != nil || old.RequireSCION || old.RequireSCIONListener {
		t.Fatalf("legacy workflow gained SCION: %+v %v", old, err)
	}
}

func TestSCIONLiteralValidation(t *testing.T) {
	for _, address := range []string{"1-ff00:0:110", "1-ff00:0:110,example.test:4000", "broken,192.0.2.1:4000", "1-ff00:0:110,192.0.2.1:0"} {
		w := Workflow{Version: 1, Name: "Invalid target", Entry: "paths", Nodes: []Node{{ID: "paths", Block: "scion_paths", Inputs: map[string]any{"address": address}}}}
		if ds := Validate(w); len(ds) == 0 {
			t.Fatalf("accepted %q", address)
		}
	}
	for _, input := range []map[string]any{{"path_id": ""}, {"max_bytes": float64(4097)}, {"encoding": "hex"}} {
		values := map[string]any{"address": "1-ff00:0:110,192.0.2.1:4000", "path_id": "path-a"}
		for k, v := range input {
			values[k] = v
		}
		if ds := Validate(Workflow{Version: 1, Name: "Invalid exchange", Entry: "exchange", Nodes: []Node{{ID: "exchange", Block: "scion_udp_exchange", Inputs: values}}}); len(ds) == 0 {
			t.Fatal("accepted", input)
		}
	}
}

func TestSCIONGeneratedGuestRequirements(t *testing.T) {
	if testing.Short() {
		t.Skip("generated guest compilation")
	}
	w := Workflow{Version: 1, Name: "SCION discovery", Entry: "paths", Nodes: []Node{{ID: "paths", Block: "scion_paths", Inputs: map[string]any{"address": "1-ff00:0:110,192.0.2.1:4000"}}}}
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source, wasm := filepath.Join(dir, "main.go"), filepath.Join(dir, "main.wasm")
	if err = os.WriteFile(source, []byte(p.Source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", wasm, source)
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("WASI guest: %v\n%s", err, raw)
	}
	binary, err := os.ReadFile(wasm)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	module, err := r.CompileModule(ctx, binary)
	if err != nil {
		t.Fatal(err)
	}
	var imports []string
	for _, f := range module.ImportedFunctions() {
		module, name, _ := f.Import()
		if module == "debuglet_io_v1" && strings.HasPrefix(name, "scion_") {
			imports = append(imports, module+"."+name)
		}
	}
	slices.Sort(imports)
	if !reflect.DeepEqual(imports, p.RequiredHostFunctions) {
		t.Fatalf("actual SCION imports %v differ from requirements %v", imports, p.RequiredHostFunctions)
	}
}

func TestSCIONComparisonTemplate(t *testing.T) {
	raw, err := os.ReadFile("../../examples/workflows/experiments/scion-path-comparison.json")
	if err != nil {
		t.Fatal(err)
	}
	var experiment Experiment
	if err = json.Unmarshal(raw, &experiment); err != nil {
		t.Fatal(err)
	}
	if ds := ValidateExperiment(experiment); len(ds) != 0 {
		t.Fatal(ds)
	}
	if len(experiment.Participants) != 2 {
		t.Fatal("comparison requires two peers")
	}
	listeners := 0
	for _, participant := range experiment.Participants {
		_, program, err := GenerateParticipant(experiment, participant.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !program.RequireSCION || program.RequireUDPListener || program.RequireICMP || len(program.Destinations) != 0 {
			t.Fatalf("incorrect dynamic peer requirements: %+v", program)
		}
		if program.RequireSCIONListener {
			listeners++
		}
	}
	if listeners != 1 {
		t.Fatalf("want one SCION listener, got %d", listeners)
	}
}
