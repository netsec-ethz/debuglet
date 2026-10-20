// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func groupedWorkflow() Workflow {
	w := sampleWorkflow()
	w.Nodes = append(w.Nodes, Node{ID: "number", Block: "constant", Inputs: map[string]any{"value": float64(42)}})
	delete(w.Nodes[0].Inputs, "value")
	w.Edges = append(w.Edges, edge("data", "number", "value", "result", "value"))
	w.Groups = []Group{{ID: "answer", Label: "Produce answer", NodeIDs: []string{"number", "result"}, Position: &Position{X: 100, Y: 200}}}
	return w
}

func TestGroupingPreservesProgramExecutionAndPortableMetadata(t *testing.T) {
	w := groupedWorkflow()
	raw, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var restored Workflow
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.Groups) != 1 || restored.Groups[0].NodeIDs[1] != "result" || restored.Groups[0].Position.Y != 200 {
		t.Fatalf("lost group metadata: %+v", restored.Groups)
	}
	grouped, err := Generate(restored)
	if err != nil {
		t.Fatal(err)
	}
	w.Groups = nil
	plain, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if grouped.WorkflowSHA256 == plain.WorkflowSHA256 {
		t.Fatal("portable graph identity must include its groups")
	}
	if strings.ReplaceAll(grouped.Source, grouped.WorkflowSHA256, plain.WorkflowSHA256) != plain.Source {
		t.Fatal("grouping changed generated execution code")
	}
}

func TestGroupingRejectsAmbiguousMembership(t *testing.T) {
	for name, change := range map[string]func(*Workflow){
		"missing member":   func(w *Workflow) { w.Groups[0].NodeIDs[0] = "absent" },
		"duplicate member": func(w *Workflow) { w.Groups[0].NodeIDs[0] = "result" },
		"overlapping groups": func(w *Workflow) {
			w.Groups = append(w.Groups, Group{ID: "other", Label: "Other", NodeIDs: []string{"number", "result"}})
		},
		"duplicate group id": func(w *Workflow) { w.Groups = append(w.Groups, w.Groups[0]) },
		"node id collision":  func(w *Workflow) { w.Groups[0].ID = "result" },
		"invalid group id":   func(w *Workflow) { w.Groups[0].ID = "../group" },
		"empty group":        func(w *Workflow) { w.Groups[0].NodeIDs = nil },
		"single member":      func(w *Workflow) { w.Groups[0].NodeIDs = []string{"result"} },
		"blank label":        func(w *Workflow) { w.Groups[0].Label = " " },
		"long label":         func(w *Workflow) { w.Groups[0].Label = strings.Repeat("x", 129) },
		"invalid position":   func(w *Workflow) { w.Groups[0].Position.X = math.Inf(1) },
	} {
		t.Run(name, func(t *testing.T) {
			w := groupedWorkflow()
			change(&w)
			if len(Validate(w)) == 0 {
				t.Fatal("accepted ambiguous grouping")
			}
		})
	}
}
