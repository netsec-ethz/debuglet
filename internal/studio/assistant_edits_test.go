// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func TestAssistantEditsPreserveUnrelatedSource(t *testing.T) {
	wf := sampleWorkflow()
	wf.Nodes[0].Position = &workflow.Position{X: 18, Y: 27}
	wf.Nodes = append(wf.Nodes, workflow.Node{ID: "tcp", Block: "tcp_connect", Inputs: map[string]any{"target": "example.test:443", "timeout_ms": float64(2000)}, Position: &workflow.Position{X: 100, Y: 200}})
	wf.CustomBlocks = []workflow.CustomBlock{{ID: "unused", Label: "Retained helper", Code: "return nil, nil"}}
	wf.Groups = []workflow.Group{{ID: "saved", Label: "Saved group", NodeIDs: []string{"result", "tcp"}}}
	raw, _ := json.Marshal(wf)
	edits := assistantEdits{Workflows: []assistantWorkflowEdits{{UpsertNodes: []assistantWireNode{{ID: "tcp", Block: "tcp_connect", InputsJSON: `{"target":"other.test:443","timeout_ms":2000}`}}}}}
	updated, err := assistantApplyEdits("workflow", raw, edits)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := DecodeWorkflow(bytes.NewReader(updated))
	if err != nil {
		t.Fatal(err)
	}
	wf.Nodes[1].Inputs["target"] = "other.test:443"
	if !reflect.DeepEqual(doc, wf) {
		t.Fatalf("input edit changed unrelated source: %#v", doc)
	}
	var original workflow.Workflow
	_ = json.Unmarshal(raw, &original)
	if original.Nodes[1].Inputs["target"] != "example.test:443" {
		t.Fatal("source snapshot mutated")
	}
}

func TestAssistantEditsRewireAndRemoveGroupedNode(t *testing.T) {
	wf := sampleWorkflow()
	wf.Entry = "tcp"
	wf.Nodes = append(wf.Nodes, workflow.Node{ID: "tcp", Block: "tcp_connect", Inputs: map[string]any{"target": "example.test:443"}})
	wf.Edges = []workflow.Edge{{Kind: "control", From: workflow.Endpoint{Node: "tcp", Port: "next"}, To: workflow.Endpoint{Node: "result", Port: "in"}}}
	wf.Groups = []workflow.Group{{ID: "only", Label: "Old report", NodeIDs: []string{"result"}}, {ID: "both", Label: "Measurements", NodeIDs: []string{"tcp", "result"}}}
	raw, _ := json.Marshal(wf)
	edits := assistantEdits{Workflows: []assistantWorkflowEdits{{
		RemoveNodes: []string{"result"},
		UpsertNodes: []assistantWireNode{{ID: "metric", Block: "report_metric", InputsJSON: `{"title":"Time","unit":"ms"}`}},
		AddEdges: []workflow.Edge{
			{Kind: "control", From: workflow.Endpoint{Node: "tcp", Port: "next"}, To: workflow.Endpoint{Node: "metric", Port: "in"}},
			{Kind: "data", From: workflow.Endpoint{Node: "tcp", Port: "duration_ms"}, To: workflow.Endpoint{Node: "metric", Port: "value"}},
		},
	}}}
	updated, err := assistantApplyEdits("workflow", raw, edits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assistantValidateDocument("workflow", updated); err != nil {
		t.Fatal(err)
	}
	doc, _ := DecodeWorkflow(bytes.NewReader(updated))
	if len(doc.Nodes) != 2 || len(doc.Edges) != 2 || len(doc.Groups) != 0 {
		t.Fatalf("node removal did not update incident edges/groups: %#v", doc)
	}
}

func TestAssistantEditsAreAtomicAcrossParticipants(t *testing.T) {
	wf := sampleWorkflow()
	experiment := workflow.Experiment{Version: 1, Kind: "experiment", Name: "Pair", Participants: []workflow.Participant{{ID: "A", Label: "First", Workflow: wf}, {ID: "B", Label: "Second", Workflow: wf}}}
	raw, _ := json.Marshal(experiment)
	before := append([]byte(nil), raw...)
	name := "Changed first"
	edits := assistantEdits{Workflows: []assistantWorkflowEdits{{Participant: "A", Name: &name}, {Participant: "B", RemoveNodes: []string{"missing"}}}}
	updated, err := assistantApplyEdits("experiment", raw, edits)
	if err == nil || updated != nil || !bytes.Equal(raw, before) {
		t.Fatalf("late invalid edit partially applied: %s %v", updated, err)
	}
	edits.Workflows = edits.Workflows[:1]
	updated, err = assistantApplyEdits("experiment", raw, edits)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := DecodeExperiment(bytes.NewReader(updated))
	if doc.Participants[0].Workflow.Name != name || !reflect.DeepEqual(doc.Participants[1], experiment.Participants[1]) || doc.Name != experiment.Name {
		t.Fatal("participant-scoped edit changed another participant")
	}
}

func TestAssistantEditsRejectAmbiguousOperations(t *testing.T) {
	wf := sampleWorkflow()
	wf.Nodes = append(wf.Nodes, workflow.Node{ID: "wait", Block: "wait", Inputs: map[string]any{"duration_ms": float64(1)}})
	edge := workflow.Edge{Kind: "control", From: workflow.Endpoint{Node: "result", Port: "next"}, To: workflow.Endpoint{Node: "wait", Port: "in"}}
	wf.Edges = []workflow.Edge{edge}
	raw, _ := json.Marshal(wf)
	node := assistantWireNode{ID: "result", Block: "emit", InputsJSON: `{"name":"answer","value":42}`}
	for name, edit := range map[string]assistantWorkflowEdits{
		"unknown participant": {Participant: "A"},
		"duplicate upsert":    {UpsertNodes: []assistantWireNode{node, node}},
		"duplicate remove":    {RemoveNodes: []string{"wait", "wait"}},
		"upsert removed":      {UpsertNodes: []assistantWireNode{node}, RemoveNodes: []string{"result"}},
		"duplicate edge":      {AddEdges: []workflow.Edge{edge}},
		"removed edge added":  {RemoveEdges: []workflow.Edge{edge}, AddEdges: []workflow.Edge{edge}},
		"missing edge":        {RemoveEdges: []workflow.Edge{{Kind: "control", From: edge.To, To: edge.From}}},
		"invalid inputs":      {UpsertNodes: []assistantWireNode{{ID: "result", Block: "emit", InputsJSON: `[]`}}},
		"excessive edits":     {UpsertNodes: make([]assistantWireNode, 513)},
	} {
		t.Run(name, func(t *testing.T) {
			if result, err := assistantApplyEdits("workflow", raw, assistantEdits{Workflows: []assistantWorkflowEdits{edit}}); err == nil || result != nil {
				t.Fatal("ambiguous edit accepted")
			}
		})
	}
	if result, err := assistantApplyEdits("workflow", raw, assistantEdits{Workflows: []assistantWorkflowEdits{{}, {}}}); err == nil || result != nil {
		t.Fatal("duplicate participant edits accepted")
	}
}
