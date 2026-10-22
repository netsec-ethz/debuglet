// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"reflect"
	"testing"
)

func iterationWorkflow(values []any) Workflow {
	return Workflow{Version: 1, Name: "Collect items", Entry: "new", Nodes: []Node{
		{ID: "new", Block: "create_collection"},
		{ID: "each", Block: "for_each", Inputs: map[string]any{"values": values}},
		{ID: "row", Block: "set_field", Inputs: map[string]any{"object": map[string]any{}, "name": "item"}},
		{ID: "indexed", Block: "set_field", Inputs: map[string]any{"name": "index"}},
		{ID: "collect", Block: "collect"},
		{ID: "read", Block: "read_collection"},
	}, Edges: []Edge{
		edge("control", "new", "next", "each", "in"), edge("control", "each", "body", "collect", "in"),
		edge("control", "each", "done", "read", "in"),
		edge("data", "each", "item", "row", "value"), edge("data", "row", "value", "indexed", "object"),
		edge("data", "each", "index", "indexed", "value"), edge("data", "indexed", "value", "collect", "value"),
		edge("data", "new", "collection", "collect", "collection"), edge("data", "new", "collection", "read", "collection"),
	}}
}

func TestGeneratedNestedForEachUsesCurrentList(t *testing.T) {
	w := iterationWorkflow(nil)
	delete(w.Nodes[1].Inputs, "values")
	w.Nodes = append(w.Nodes, Node{ID: "outer", Block: "for_each", Inputs: map[string]any{"values": []any{[]any{"a"}, []any{}, []any{"b", "c"}}}})
	w.Edges[0] = edge("control", "new", "next", "outer", "in")
	w.Edges[2] = edge("control", "outer", "done", "read", "in")
	w.Edges = append(w.Edges, edge("control", "outer", "body", "each", "in"), edge("data", "outer", "item", "each", "values"))
	outputs, counts := executeReportWorkflow(t, w)
	want := []any{map[string]any{"item": "a", "index": float64(0)}, map[string]any{"item": "b", "index": float64(0)}, map[string]any{"item": "c", "index": float64(1)}}
	if !reflect.DeepEqual(outputs["read"]["values"], want) || counts["collect"] != 3 || counts["read_collection"] != 1 {
		t.Fatalf("nested iteration results: %v; actions: %v", outputs["read"], counts)
	}
}

func TestGeneratedForEachExecutesWASI(t *testing.T) {
	for name, values := range map[string][]any{"mixed": {"a", float64(9), nil}, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			outputs, counts := executeReportWorkflow(t, iterationWorkflow(values))
			want := make([]any, len(values))
			for i, value := range values {
				want[i] = map[string]any{"item": value, "index": float64(i)}
			}
			if !reflect.DeepEqual(outputs["read"]["values"], want) || counts["collect"] != len(values) || counts["read_collection"] != 1 {
				t.Fatalf("iteration results: %v; actions: %v", outputs["read"], counts)
			}
		})
	}
}

func TestForEachValidationBoundsAndScope(t *testing.T) {
	for name, change := range map[string]func(*Workflow){
		"not a list": func(w *Workflow) { w.Nodes[1].Inputs["values"] = "one" },
		"too many":   func(w *Workflow) { w.Nodes[1].Inputs["values"] = make([]any, 101) },
		"direct escape": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "out", Block: "emit", Inputs: map[string]any{"name": "item"}})
			w.Edges = append(w.Edges, edge("data", "each", "item", "out", "value"))
		},
		"pure escape": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "out", Block: "emit", Inputs: map[string]any{"name": "row"}})
			w.Edges = append(w.Edges, edge("data", "indexed", "value", "out", "value"))
		},
		"body escape": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "out", Block: "emit", Inputs: map[string]any{"name": "count"}})
			w.Edges = append(w.Edges, edge("data", "collect", "count", "out", "value"))
		},
		"control escape": func(w *Workflow) { w.Edges = append(w.Edges, edge("control", "collect", "next", "read", "in")) },
		"body entry":     func(w *Workflow) { w.Entry = "collect" },
	} {
		t.Run(name, func(t *testing.T) {
			w := iterationWorkflow([]any{})
			change(&w)
			if ds := Validate(w); len(ds) == 0 {
				t.Fatal("accepted invalid iteration")
			}
		})
	}
	w := iterationWorkflow(make([]any, 100))
	if ds := Validate(w); len(ds) != 0 {
		t.Fatal(ds)
	}
	// Values supplied by a preceding block remain checked at runtime.
	delete(w.Nodes[1].Inputs, "values")
	w.Nodes = append(w.Nodes, Node{ID: "list", Block: "constant", Inputs: map[string]any{"value": []any{}}})
	w.Edges = append(w.Edges, edge("data", "list", "value", "each", "values"))
	if ds := Validate(w); len(ds) != 0 {
		t.Fatal(ds)
	}
	if _, err := Generate(w); err != nil {
		t.Fatal(err)
	}
}
