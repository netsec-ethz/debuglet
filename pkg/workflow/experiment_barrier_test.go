// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"strings"
	"testing"
)

func barrierExperiment() Experiment {
	e := Experiment{Version: 1, Kind: "experiment", Name: "Repeated phase"}
	for _, id := range []string{"A", "B", "C"} {
		e.Participants = append(e.Participants, Participant{ID: id, Workflow: Workflow{
			Version: 1, Name: id, Entry: "phase",
			Nodes: []Node{{ID: "phase", Block: "phase_barrier", Inputs: map[string]any{"phase": "sample"}}},
		}})
	}
	return e
}

func TestExperimentBarrierRequiresSharedLiteralPhases(t *testing.T) {
	if ds := ValidateExperiment(barrierExperiment()); len(ds) != 0 {
		t.Fatal(ds)
	}
	for name, edit := range map[string]func(*Experiment){
		"other phase":            func(e *Experiment) { e.Participants[0].Workflow.Nodes[0].Inputs["phase"] = "other" },
		"empty phase":            func(e *Experiment) { e.Participants[0].Workflow.Nodes[0].Inputs["phase"] = "" },
		"surrounding whitespace": func(e *Experiment) { e.Participants[0].Workflow.Nodes[0].Inputs["phase"] = " sample" },
		"too long":               func(e *Experiment) { e.Participants[0].Workflow.Nodes[0].Inputs["phase"] = strings.Repeat("x", 65) },
		"wired phase": func(e *Experiment) {
			w := &e.Participants[0].Workflow
			delete(w.Nodes[0].Inputs, "phase")
			w.Nodes = append(w.Nodes, Node{ID: "name", Block: "constant", Inputs: map[string]any{"value": "sample"}})
			w.Edges = append(w.Edges, edge("data", "name", "value", "phase", "phase"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := barrierExperiment()
			edit(&e)
			if len(ValidateExperiment(e)) == 0 {
				t.Fatal("accepted mismatched or dynamic phase")
			}
		})
	}
}
