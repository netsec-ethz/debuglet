// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func sampleWorkflow() Workflow {
	return Workflow{Version: 1, Name: "Sample", Entry: "result", Nodes: []Node{{ID: "result", Block: "emit", Inputs: map[string]any{"name": "answer", "value": float64(42)}}}, Edges: []Edge{}}
}
func edge(kind, from, port, to, input string) Edge {
	return Edge{kind, Endpoint{from, port}, Endpoint{to, input}}
}
func TestValidationRejectsAmbiguousAndUnsafeGraphs(t *testing.T) {
	cases := map[string]func(*Workflow){
		"unknown block":   func(w *Workflow) { w.Nodes[0].Block = "missing" },
		"duplicate node":  func(w *Workflow) { w.Nodes = append(w.Nodes, w.Nodes[0]) },
		"unknown literal": func(w *Workflow) { w.Nodes[0].Inputs["typo"] = true },
		"fractional timeout": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "http", Block: "http", Inputs: map[string]any{"url": "https://example.test", "timeout_ms": 1.5}})
		},
		"wrong type":    func(w *Workflow) { w.Nodes[0].Inputs["name"] = float64(1) },
		"missing input": func(w *Workflow) { delete(w.Nodes[0].Inputs, "name") },
		"control cycle": func(w *Workflow) { w.Edges = append(w.Edges, edge("control", "result", "next", "result", "in")) },
		"literal and wire": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "c", Block: "constant", Inputs: map[string]any{"value": true}})
			w.Edges = append(w.Edges, edge("data", "c", "value", "result", "value"))
		},
		"data cycle": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "c", Block: "constant"})
			delete(w.Nodes[0].Inputs, "value")
			w.Edges = append(w.Edges, edge("data", "c", "value", "result", "value"), edge("data", "result", "value", "c", "value"))
		},
		"code escapes function": func(w *Workflow) {
			w.CustomBlocks = []CustomBlock{{ID: "bad", Label: "Bad", Code: "return nil,nil\n}\nfunc init(){ panic(\"escape\") }\nfunc other(){"}}
		},
		"large custom default": func(w *Workflow) {
			w.CustomBlocks = []CustomBlock{{ID: "bad", Label: "Bad", Inputs: []Port{{Name: "text", Type: "string", Default: strings.Repeat("a", 16385)}}, Code: "return nil,nil"}}
		},
		"compiler directive": func(w *Workflow) {
			w.CustomBlocks = []CustomBlock{{ID: "bad", Label: "Bad", Code: "//go:linkname hidden\nreturn nil,nil"}}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := sampleWorkflow()
			change(&w)
			if ds := Validate(w); len(ds) == 0 {
				t.Fatal("accepted invalid graph")
			}
		})
	}
}
func TestRepeatBodyCannotEscape(t *testing.T) {
	w := Workflow{Version: 1, Name: "Repeat", Entry: "repeat", Nodes: []Node{{ID: "repeat", Block: "repeat", Inputs: map[string]any{"count": float64(2)}}, {ID: "body", Block: "wait", Inputs: map[string]any{"duration_ms": float64(0)}}, {ID: "done", Block: "emit", Inputs: map[string]any{"name": "done", "value": true}}}, Edges: []Edge{edge("control", "repeat", "body", "body", "in"), edge("control", "repeat", "done", "done", "in")}}
	if ds := Validate(w); len(ds) > 0 {
		t.Fatal(ds)
	}
	w.Edges = append(w.Edges, edge("control", "body", "next", "done", "in"))
	if ds := Validate(w); len(ds) == 0 {
		t.Fatal("accepted body escaping to done")
	}
}
func TestExampleProgramsGenerate(t *testing.T) {
	files, err := filepath.Glob("../../examples/workflows/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if filepath.Base(file) == "catalog.json" {
			continue
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var w Workflow
			if err = json.Unmarshal(raw, &w); err != nil {
				t.Fatal(err)
			}
			if ds := Validate(w); len(ds) > 0 {
				t.Fatal(ds)
			}
			program, err := Generate(w)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = parser.ParseFile(token.NewFileSet(), "main.go", program.Source, parser.AllErrors); err != nil {
				t.Fatal(err)
			}
			if len(program.WorkflowSHA256) != 64 {
				t.Fatal("missing digest")
			}
			if filepath.Base(file) == "ping-branch.json" && !program.RequireICMP {
				t.Fatal("Ping missing ICMP requirement")
			}
		})
	}
}
func TestDestinationHints(t *testing.T) {
	w := Workflow{Version: 1, Name: "Targets", Entry: "http", Nodes: []Node{{ID: "http", Block: "http", Inputs: map[string]any{"url": "https://example.test:8443/a"}}, {ID: "tcp", Block: "tcp_connect", Inputs: map[string]any{"target": "127.0.0.1:1234"}}}, Edges: []Edge{edge("control", "http", "next", "tcp", "in")}}
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Destinations, ",") != "127.0.0.1,example.test" {
		t.Fatal(p.Destinations)
	}
}

// Running generated code catches mistakes that syntax-only generation tests miss.
func TestGeneratedProgramExecutesBranchesAndRepeat(t *testing.T) {
	if testing.Short() {
		t.Skip("generated program compilation")
	}
	w := Workflow{Version: 1, Name: "Bounded branch", Entry: "custom", CustomBlocks: []CustomBlock{{ID: "shadowed", Label: "Shadowed name", Inputs: []Port{}, Outputs: []Port{{Name: "value", Type: "string"}}, Code: "strings := struct{Value string}{\"ok\"}; return map[string]any{\"value\":strings.Value},nil"}}, Nodes: []Node{
		{ID: "custom", Block: "shadowed"},
		{ID: "repeat", Block: "repeat", Inputs: map[string]any{"count": float64(3)}},
		{ID: "compare", Block: "greater_than", Inputs: map[string]any{"b": float64(1)}},
		{ID: "branch", Block: "if"},
		{ID: "yes", Block: "emit", Inputs: map[string]any{"name": "later"}},
		{ID: "no", Block: "emit", Inputs: map[string]any{"name": "first"}},
		{ID: "done", Block: "emit", Inputs: map[string]any{"name": "done", "value": true}},
	}, Edges: []Edge{edge("control", "custom", "next", "repeat", "in"), edge("control", "repeat", "body", "branch", "in"), edge("control", "repeat", "done", "done", "in"), edge("data", "repeat", "iteration", "compare", "a"), edge("data", "compare", "value", "branch", "condition"), edge("control", "branch", "true", "yes", "in"), edge("control", "branch", "false", "no", "in"), edge("data", "repeat", "iteration", "yes", "value"), edge("data", "repeat", "iteration", "no", "value")}}
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err = os.WriteFile(source, []byte(p.Source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", source)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated program failed: %v\n%s", err, out)
	}
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var e struct {
			Status string `json:"status"`
			Node   string `json:"node_id"`
		}
		if err = json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Status != "completed" {
			t.Fatal(string(line))
		}
		counts[e.Node]++
	}
	if counts["yes"] != 2 || counts["no"] != 1 || counts["done"] != 1 {
		t.Fatal(counts)
	}
}

func TestCatalogFixtureMatches(t *testing.T) {
	raw, err := os.ReadFile("../../examples/workflows/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture []Block
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(Catalog(), fixture) {
		t.Fatal("catalog fixture differs from Catalog()")
	}
}
