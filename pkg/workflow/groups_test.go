// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
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

func nestedGroupedWorkflow() Workflow {
	w := groupedWorkflow()
	w.Nodes = append(w.Nodes,
		Node{ID: "other", Block: "constant", Inputs: map[string]any{"value": float64(1)}},
		Node{ID: "flag", Block: "constant", Inputs: map[string]any{"value": true}},
	)
	// Parent order is deliberately unrelated to depth.
	w.Groups = append([]Group{{ID: "summary", Label: "Summary", NodeIDs: []string{"result", "other", "number"}}}, w.Groups...)
	w.Groups = append(w.Groups, Group{ID: "all", Label: "All", NodeIDs: []string{"flag", "result", "other", "number"}})
	return w
}

func TestGroupingPreservesProgramExecutionAndPortableMetadata(t *testing.T) {
	for name, w := range map[string]Workflow{"flat": groupedWorkflow(), "nested": nestedGroupedWorkflow()} {
		t.Run(name, func(t *testing.T) {
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
			if !reflect.DeepEqual(restored.Groups, w.Groups) {
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
		})
	}
}

func TestGroupingRejectsAmbiguousMembership(t *testing.T) {
	for name, change := range map[string]func(*Workflow){
		"missing member":   func(w *Workflow) { w.Groups[0].NodeIDs[0] = "absent" },
		"duplicate member": func(w *Workflow) { w.Groups[0].NodeIDs[0] = "result" },
		"equal member sets": func(w *Workflow) {
			w.Groups = append(w.Groups, Group{ID: "other", Label: "Other", NodeIDs: []string{"number", "result"}})
		},
		"partial overlap": func(w *Workflow) {
			w.Nodes = append(w.Nodes, Node{ID: "other", Block: "constant", Inputs: map[string]any{"value": true}})
			w.Groups = append(w.Groups, Group{ID: "other_group", Label: "Other", NodeIDs: []string{"result", "other"}})
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

func TestPresentationCountsEachHierarchyLevel(t *testing.T) {
	w := nestedGroupedWorkflow()
	if ds := Validate(w); len(ds) != 0 {
		t.Fatalf("nested graph: %v", ds)
	}
	if ds := ValidatePresentation(w, 2); len(ds) != 0 {
		t.Fatalf("each nested view has at most two cards: %v", ds)
	}
	for _, group := range w.Groups {
		if len(group.NodeIDs) > 2 && len(ValidatePresentation(Workflow{Nodes: w.Nodes, Groups: []Group{group}}, 2)) == 0 {
			t.Fatal("a large group must not hide an oversized inner view")
		}
	}

	flat := sampleWorkflow()
	for i := 1; i < 11; i++ {
		flat.Nodes = append(flat.Nodes, Node{ID: fmt.Sprintf("n%d", i), Block: "constant", Inputs: map[string]any{"value": i}})
	}
	if ds := Validate(flat); len(ds) != 0 {
		t.Fatalf("presentation cap restricted a manual graph: %v", ds)
	}
	if ds := ValidatePresentation(flat, 10); len(ds) != 1 || !strings.Contains(ds[0].Message, "overview shows 11") {
		t.Fatalf("oversized overview: %v", ds)
	}
	members := make([]string, len(flat.Nodes))
	for i, node := range flat.Nodes {
		members[i] = node.ID
	}
	flat.Groups = []Group{{ID: "all", Label: "All", NodeIDs: members}}
	if ds := ValidatePresentation(flat, 10); len(ds) != 1 || !strings.Contains(ds[0].Message, "group all shows 11") {
		t.Fatalf("oversized inner view: %v", ds)
	}
	flat.Groups[0].NodeIDs = members[:10]
	if ds := ValidatePresentation(flat, 10); len(ds) != 0 {
		t.Fatalf("ten cards in group, two at overview: %v", ds)
	}
	flat.Groups = append(flat.Groups, flat.Groups[0])
	if ds := ValidatePresentation(flat, 10); len(ds) == 0 {
		t.Fatal("invalid group tree accepted by presentation check")
	}
	if ds := ValidatePresentation(sampleWorkflow(), 0); len(ds) == 0 {
		t.Fatal("invalid visible limit accepted")
	}
}
