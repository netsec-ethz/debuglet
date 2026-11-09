// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"fmt"
	"strings"
	"testing"
)

// The first connection can fail while the second succeeds. Skipping local
// must not turn the later comparison into a read of an unexecuted action.
func availabilityWorkflow() Workflow {
	return Workflow{Version: 1, Name: "Guarded comparison", Entry: "first", Nodes: []Node{
		{ID: "first", Block: "tcp_connect", Inputs: map[string]any{"target": "first.example:443"}},
		{ID: "second", Block: "tcp_connect", Inputs: map[string]any{"target": "second.example:443"}},
		{ID: "gate", Block: "if"},
		{ID: "local", Block: "tcp_connect", Inputs: map[string]any{"target": "local.example:443"}},
		{ID: "recheck", Block: "if"},
		{ID: "difference", Block: "subtract"},
		{ID: "report", Block: "report_metric", Inputs: map[string]any{"title": "Difference", "unit": "ms"}},
		{ID: "failure", Block: "emit", Inputs: map[string]any{"name": "failure"}},
	}, Edges: []Edge{
		edge("control", "first", "next", "second", "in"), edge("control", "second", "next", "gate", "in"),
		edge("control", "gate", "true", "local", "in"), edge("control", "gate", "false", "recheck", "in"),
		edge("control", "local", "next", "recheck", "in"), edge("control", "recheck", "true", "report", "in"),
		edge("control", "recheck", "false", "failure", "in"),
		edge("data", "first", "ok", "gate", "condition"), edge("data", "second", "ok", "recheck", "condition"),
		edge("data", "local", "duration_ms", "difference", "a"), edge("data", "second", "duration_ms", "difference", "b"),
		edge("data", "difference", "value", "report", "value"), edge("data", "first", "error", "failure", "value"),
	}}
}

func availabilityInput(w *Workflow, node, port string, source Endpoint) {
	for i, e := range w.Edges {
		if e.Kind == "data" && e.To == (Endpoint{node, port}) {
			w.Edges[i].From = source
			return
		}
	}
}

func availabilityCheck(t *testing.T, w Workflow, node, port string) {
	t.Helper()
	if ds := Validate(w); len(ds) != 0 {
		t.Fatalf("fixture is structurally invalid: %+v", ds)
	}
	ds := ValidateOutputAvailability(w)
	if node == "" {
		if len(ds) != 0 {
			t.Fatalf("rejected a supported guarded workflow: %+v", ds)
		}
		return
	}
	for _, d := range ds {
		if d.Node == node && d.Port == port && strings.Contains(d.Message, "local") {
			return
		}
	}
	t.Fatalf("missing unavailable-output diagnostic for %s.%s: %+v", node, port, ds)
}

func TestOutputAvailabilityRejectsSkippedActionThroughPureData(t *testing.T) {
	w := availabilityWorkflow()
	availabilityCheck(t, w, "report", "value")
	// This opt-in assistant preflight must not change existing build acceptance
	// for manually authored graphs with correlations hidden in custom code.
	if _, err := Generate(w); err != nil {
		t.Fatalf("ordinary generation changed: %v", err)
	}
}

func TestOutputAvailabilityChecksBothInputsOfAnd(t *testing.T) {
	for _, otherFalse := range []bool{false, true} {
		t.Run(fmt.Sprintf("other_literal_false_%t", otherFalse), func(t *testing.T) {
			w := availabilityWorkflow()
			both := Node{ID: "both", Block: "and", Inputs: map[string]any{}}
			if otherFalse {
				both.Inputs["a"] = false
			} else {
				w.Edges = append(w.Edges, edge("data", "second", "ok", "both", "a"))
			}
			w.Nodes = append(w.Nodes, both)
			w.Edges = append(w.Edges, edge("data", "local", "ok", "both", "b"))
			availabilityInput(&w, "recheck", "condition", Endpoint{"both", "value"})
			availabilityCheck(t, w, "recheck", "condition")
		})
	}
}

func TestOutputAvailabilityPreservesCorrelatedGuardsAndFailures(t *testing.T) {
	for _, operation := range []string{"same", "not", "and", "or"} {
		t.Run(operation, func(t *testing.T) {
			w := availabilityWorkflow()
			availabilityInput(&w, "recheck", "condition", Endpoint{"first", "ok"})
			if operation == "not" {
				w.Nodes = append(w.Nodes, Node{ID: "op", Block: "not"})
				w.Edges = append(w.Edges, edge("data", "first", "ok", "op", "value"))
				availabilityInput(&w, "recheck", "condition", Endpoint{"op", "value"})
				for i, e := range w.Edges {
					if e.Kind == "control" && e.From.Node == "recheck" {
						if e.From.Port == "true" {
							w.Edges[i].From.Port = "false"
						} else {
							w.Edges[i].From.Port = "true"
						}
					}
				}
			} else if operation != "same" {
				// Equivalent expressions in distinct pure nodes retain the same
				// action-output facts; node identity is not the correlation.
				for _, id := range []string{"op1", "op2"} {
					w.Nodes = append(w.Nodes, Node{ID: id, Block: operation})
					w.Edges = append(w.Edges, edge("data", "first", "ok", id, "a"), edge("data", "second", "ok", id, "b"))
				}
				availabilityInput(&w, "gate", "condition", Endpoint{"op1", "value"})
				availabilityInput(&w, "recheck", "condition", Endpoint{"op2", "value"})
			}
			availabilityCheck(t, w, "", "")
		})
	}
}

func TestOutputAvailabilityLeavesUnsupportedPredicatesAndLoopsAlone(t *testing.T) {
	w := availabilityWorkflow()
	w.Nodes = append(w.Nodes, Node{ID: "comparison", Block: "greater_than", Inputs: map[string]any{"b": float64(0)}})
	w.Edges = append(w.Edges, edge("data", "first", "duration_ms", "comparison", "a"))
	availabilityInput(&w, "gate", "condition", Endpoint{"comparison", "value"})
	availabilityCheck(t, w, "", "")
	availabilityCheck(t, iterationWorkflow([]any{"one", "two"}), "", "")
}

func TestOutputAvailabilityChecksPrefixUntilLoop(t *testing.T) {
	for _, scenario := range []string{"unused", "after prefix", "other branch", "loop input", "after loop"} {
		t.Run(scenario, func(t *testing.T) {
			w := availabilityWorkflow()
			w.Nodes = append(w.Nodes,
				Node{ID: "loop", Block: "repeat", Inputs: map[string]any{"count": float64(2)}},
				Node{ID: "body", Block: "emit", Inputs: map[string]any{"name": "iteration", "value": true}},
			)
			w.Edges = append(w.Edges, edge("control", "loop", "body", "body", "in"))
			node, port := "report", "value"
			switch scenario {
			case "after prefix":
				w.Edges = append(w.Edges, edge("control", "report", "next", "loop", "in"))
			case "other branch":
				w.Entry = "start"
				w.Nodes = append(w.Nodes,
					Node{ID: "start", Block: "tcp_connect", Inputs: map[string]any{"target": "start.example:443"}},
					Node{ID: "choose", Block: "if"},
				)
				w.Edges = append(w.Edges,
					edge("control", "start", "next", "choose", "in"), edge("data", "start", "ok", "choose", "condition"),
					edge("control", "choose", "false", "loop", "in"), edge("control", "choose", "true", "first", "in"),
				)
			case "loop input":
				w.Entry = "loop"
				delete(w.Nodes[len(w.Nodes)-2].Inputs, "count")
				w.Edges = append(w.Edges, edge("data", "local", "duration_ms", "loop", "count"))
				node, port = "loop", "count"
			case "after loop":
				w.Entry = "loop"
				w.Edges = append(w.Edges, edge("control", "loop", "done", "first", "in"))
				node, port = "", "" // No claim about paths after an unmodeled loop.
			}
			availabilityCheck(t, w, node, port)
		})
	}
}

func TestOutputAvailabilityPrunesLiteralBranchesAndIgnoresUnusedNodes(t *testing.T) {
	w := availabilityWorkflow()
	w.Nodes = append(w.Nodes, Node{ID: "literal", Block: "constant", Inputs: map[string]any{"value": true}})
	availabilityInput(&w, "gate", "condition", Endpoint{"literal", "value"})
	availabilityCheck(t, w, "", "")
	// The entire unsafe subgraph is an unused editor fragment.
	w.Entry = "unrelated"
	w.Nodes = append(w.Nodes, Node{ID: "unrelated", Block: "emit", Inputs: map[string]any{"name": "done", "value": true}})
	availabilityCheck(t, w, "", "")
}

func TestOutputAvailabilityPreservesReportedFailure(t *testing.T) {
	w := Workflow{Version: 1, Name: "Retain failed measurement", Entry: "probe", CustomBlocks: []CustomBlock{{
		ID: "failed_probe", Label: "Failed measurement",
		Outputs: []Port{{Name: "ok", Type: "boolean"}, {Name: "error", Type: "string"}},
		Code:    `return map[string]any{"ok": false, "error": "connection refused"}, nil`,
	}}, Nodes: []Node{
		{ID: "probe", Block: "failed_probe"}, {ID: "gate", Block: "if"},
		{ID: "success", Block: "emit", Inputs: map[string]any{"name": "success", "value": true}},
		{ID: "failure", Block: "emit", Inputs: map[string]any{"name": "failure"}},
	}, Edges: []Edge{
		edge("control", "probe", "next", "gate", "in"), edge("data", "probe", "ok", "gate", "condition"),
		edge("control", "gate", "true", "success", "in"), edge("control", "gate", "false", "failure", "in"),
		edge("data", "probe", "error", "failure", "value"),
	}}
	availabilityCheck(t, w, "", "")
	outputs, _ := executeReportWorkflow(t, w)
	if outputs["probe"]["ok"] != false || outputs["probe"]["error"] != "connection refused" || outputs["failure"]["value"] != "connection refused" || outputs["success"] != nil {
		t.Fatalf("failure path lost its observed result: %+v", outputs)
	}
}

func TestOutputAvailabilityBudgetDiscardsPartialAnalysis(t *testing.T) {
	w := availabilityWorkflow()
	availabilityCheck(t, w, "report", "value")
	// The first branch is unsafe. The second has many independent Boolean
	// choices; exhausting the bounded preflight must not certify partial work.
	w.Entry = "start"
	w.Nodes = append(w.Nodes, Node{ID: "start", Block: "tcp_connect", Inputs: map[string]any{"target": "start.example:443"}}, Node{ID: "choose", Block: "if"})
	w.Edges = append(w.Edges, edge("control", "start", "next", "choose", "in"), edge("data", "start", "ok", "choose", "condition"), edge("control", "choose", "false", "first", "in"), edge("control", "choose", "true", "p0", "in"))
	for i := 0; i < 14; i++ {
		probe, branch, next := fmt.Sprintf("p%d", i), fmt.Sprintf("b%d", i), fmt.Sprintf("p%d", i+1)
		w.Nodes = append(w.Nodes, Node{ID: probe, Block: "tcp_connect", Inputs: map[string]any{"target": "branch.example:443"}}, Node{ID: branch, Block: "if"})
		w.Edges = append(w.Edges, edge("control", probe, "next", branch, "in"), edge("data", probe, "ok", branch, "condition"))
		if i < 13 {
			w.Edges = append(w.Edges, edge("control", branch, "true", next, "in"), edge("control", branch, "false", next, "in"))
		}
	}
	availabilityCheck(t, w, "", "")
}
