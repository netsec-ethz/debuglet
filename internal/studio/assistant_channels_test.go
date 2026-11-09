// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func assistantChannelRepairFixture(t *testing.T) (workflow.Experiment, assistantEdits, workflow.Experiment) {
	t.Helper()
	want := workflow.Experiment{Version: 1, Kind: "experiment", Name: "Exchange", Channels: []workflow.Channel{
		{ID: "a_to_b", From: "A", To: "B", Type: "number"},
		{ID: "b_to_a", From: "B", To: "A", Type: "number"},
	}}
	for i, id := range []string{"A", "B"} {
		peer := []string{"B", "A"}[i]
		wf := sampleWorkflow()
		wf.Entry = "send"
		wf.Nodes[0].Position = &workflow.Position{X: 80, Y: 130}
		wf.Nodes = append([]workflow.Node{
			{ID: "send", Block: "send_message", Inputs: map[string]any{"destination": peer, "channel": want.Channels[i].ID, "value": float64(21), "timeout_ms": float64(2000)}, Position: &workflow.Position{X: 20, Y: 30}},
			{ID: "await", Block: "await_message", Inputs: map[string]any{"source": peer, "channel": want.Channels[1-i].ID, "timeout_ms": float64(2000)}},
		}, wf.Nodes...)
		wf.Edges = []workflow.Edge{{Kind: "control", From: workflow.Endpoint{Node: "send", Port: "next"}, To: workflow.Endpoint{Node: "await", Port: "in"}}}
		wf.CustomBlocks = []workflow.CustomBlock{{ID: "retained", Label: "Retained helper", Inputs: []workflow.Port{}, Outputs: []workflow.Port{}, Code: "return map[string]any{}, nil"}}
		want.Participants = append(want.Participants, workflow.Participant{ID: id, Label: "Participant " + id, Workflow: wf})
	}
	raw, _ := json.Marshal(want)
	bad, err := DecodeExperiment(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	bad.Channels[0].ID = "shared"
	bad.Channels[1] = bad.Channels[0]
	edits := assistantEdits{Channels: &want.Channels}
	for i := range bad.Participants {
		bad.Participants[i].Workflow.Nodes[0].Inputs["channel"] = "shared"
		bad.Participants[i].Workflow.Nodes[1].Inputs["channel"] = "shared"
		wire := assistantWireFixture(t, want.Participants[i].Workflow)
		for j := range wire.Nodes[:2] {
			wire.Nodes[j].Position = nil
		}
		edits.Workflows = append(edits.Workflows, assistantWorkflowEdits{Participant: want.Participants[i].ID, UpsertNodes: wire.Nodes[:2]})
	}
	return bad, edits, want
}

func TestAssistantChannelRepairPreservesUnrelatedSource(t *testing.T) {
	bad, edits, want := assistantChannelRepairFixture(t)
	raw, _ := json.Marshal(bad)
	before := append([]byte(nil), raw...)
	if _, err := assistantValidateDocument("experiment", raw); err == nil {
		t.Fatal("fixture must require channel repair")
	}
	channelsOnly, err := assistantApplyEdits("experiment", raw, assistantEdits{Channels: edits.Channels})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assistantValidateDocument("experiment", channelsOnly); err == nil {
		t.Fatal("channel replacement must also repair dependent node references")
	}
	updated, err := assistantApplyEdits("experiment", raw, edits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assistantValidateDocument("experiment", updated); err != nil {
		t.Fatal(err)
	}
	doc, err := DecodeExperiment(bytes.NewReader(updated))
	if err != nil || !reflect.DeepEqual(doc, want) || !bytes.Equal(raw, before) {
		t.Fatalf("channel repair changed unrelated source or original: %v", err)
	}
	// A failure after replacing channels and editing the first participant must
	// not expose the partially repaired candidate or mutate its source snapshot.
	edits.Workflows[1].RemoveNodes = []string{"missing"}
	if result, err := assistantApplyEdits("experiment", raw, edits); err == nil || result != nil || !bytes.Equal(raw, before) {
		t.Fatal("late workflow failure exposed partial channel replacement")
	}
}

func TestAssistantChannelEditBoundary(t *testing.T) {
	wf, _ := json.Marshal(sampleWorkflow())
	empty := []workflow.Channel{}
	if result, err := assistantApplyEdits("workflow", wf, assistantEdits{Channels: &empty}); err == nil || result != nil {
		t.Fatal("ordinary workflow accepted channels")
	}
	tooMany := make([]workflow.Channel, 513)
	experiment := workflow.Experiment{Version: 1, Kind: "experiment", Name: "Independent", Participants: []workflow.Participant{{ID: "A", Workflow: sampleWorkflow()}, {ID: "B", Workflow: sampleWorkflow()}}, Channels: []workflow.Channel{{ID: "unused", From: "A", To: "B", Type: "number"}}}
	raw, _ := json.Marshal(experiment)
	if result, err := assistantApplyEdits("experiment", raw, assistantEdits{Channels: &tooMany}); err == nil || result != nil {
		t.Fatal("replacement channels escaped operation limit")
	}
	for _, channels := range []*[]workflow.Channel{nil, &empty} {
		updated, err := assistantApplyEdits("experiment", raw, assistantEdits{Channels: channels})
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := DecodeExperiment(bytes.NewReader(updated))
		if channels == nil && !reflect.DeepEqual(doc.Channels, experiment.Channels) || channels != nil && len(doc.Channels) != 0 {
			t.Fatal("null must preserve channels; an empty list must clear them")
		}
	}
}

func TestAssistantRepairsChannelsWithIncrementalReply(t *testing.T) {
	bad, edits, want := assistantChannelRepairFixture(t)
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			participants := make([]any, 0, len(bad.Participants))
			for _, participant := range bad.Participants {
				participants = append(participants, map[string]any{"id": participant.ID, "label": participant.Label, "workflow": assistantWireFixture(t, participant.Workflow)})
			}
			assistantToolReply(w, map[string]any{"message": "Exchange values.", "action": "", "document": map[string]any{"version": bad.Version, "kind": bad.Kind, "name": bad.Name, "participants": participants, "channels": bad.Channels}})
			return
		}
		var request struct {
			Messages []assistantModelMessage `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		} else if !strings.Contains(request.Messages[len(request.Messages)-1].Content, "corrected complete compact document") {
			t.Error("structural correction does not request a complete proposal")
		}
		assistantToolReply(w, map[string]any{"message": "Corrected channel directions.", "action": "", "document": nil, "edits": edits})
	})
	client.strictSchema = true
	result, err := client.Reply(t.Context(), assistantInput(t, "experiment", want))
	if err != nil || calls.Load() != 2 {
		t.Fatalf("incremental channel correction failed: %v", err)
	}
	doc, err := DecodeExperiment(bytes.NewReader(result.Document))
	if err != nil || !reflect.DeepEqual(doc, want) {
		t.Fatalf("channel-only correction failed to preserve the experiment: %v", err)
	}
}
