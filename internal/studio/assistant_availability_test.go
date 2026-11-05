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

func TestAssistantRepairsSkippedActionOutputRead(t *testing.T) {
	bypass := workflow.Edge{Kind: "control", From: workflow.Endpoint{Node: "gate", Port: "false"}, To: workflow.Endpoint{Node: "report", Port: "in"}}
	bad := workflow.Workflow{Version: 1, Name: "Conditional measurement", Entry: "gate", Nodes: []workflow.Node{
		{ID: "gate", Block: "if", Inputs: map[string]any{"condition": false}},
		{ID: "tcp", Block: "tcp_connect", Inputs: map[string]any{"target": "example.org:443"}},
		{ID: "report", Block: "report_metric", Inputs: map[string]any{"title": "Connection time", "unit": "ms"}},
	}, Edges: []workflow.Edge{
		{Kind: "control", From: workflow.Endpoint{Node: "gate", Port: "true"}, To: workflow.Endpoint{Node: "tcp", Port: "in"}},
		{Kind: "control", From: workflow.Endpoint{Node: "tcp", Port: "next"}, To: workflow.Endpoint{Node: "report", Port: "in"}},
		{Kind: "data", From: workflow.Endpoint{Node: "tcp", Port: "duration_ms"}, To: workflow.Endpoint{Node: "report", Port: "value"}},
		bypass,
	}}
	if ds := workflow.Validate(bad); len(ds) != 0 {
		t.Fatalf("fixture must pass ordinary graph validation: %v", ds)
	}
	for _, kind := range []string{"workflow", "experiment"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					var document any = assistantWireFixture(t, bad)
					if kind == "experiment" {
						document = map[string]any{"version": 1, "kind": kind, "name": "Comparison", "channels": []workflow.Channel{}, "participants": []any{
							map[string]any{"id": "probe", "workflow": document},
							map[string]any{"id": "other", "workflow": assistantWireFixture(t, sampleWorkflow())},
						}}
					}
					assistantToolReply(w, map[string]any{"message": "Conditional comparison.", "document": document})
					return
				}
				var body struct {
					Messages []assistantModelMessage `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				feedback := body.Messages[len(body.Messages)-1].Content
				if !strings.Contains(feedback, "report") || !strings.Contains(feedback, "tcp") || kind == "experiment" && !strings.Contains(feedback, "probe") {
					t.Errorf("repair feedback did not identify the unavailable output: %s", feedback)
				}
				participant := ""
				if kind == "experiment" {
					participant = "probe"
				}
				assistantToolReply(w, map[string]any{"message": "Skip the report when the measurement did not execute.", "edits": assistantEdits{Workflows: []assistantWorkflowEdits{{Participant: participant, RemoveEdges: []workflow.Edge{bypass}}}}})
			})
			client.strictSchema = true
			var original any = sampleWorkflow()
			if kind == "experiment" {
				original = workflow.Experiment{Version: 1, Kind: kind, Name: "Comparison", Participants: []workflow.Participant{{ID: "probe", Workflow: sampleWorkflow()}, {ID: "other", Workflow: sampleWorkflow()}}, Channels: []workflow.Channel{}}
			}
			result, err := client.Reply(t.Context(), assistantInput(t, kind, original))
			if err != nil || calls.Load() != 2 {
				t.Fatalf("conditional repair failed: %v", err)
			}
			var got workflow.Workflow
			if kind == "workflow" {
				got, err = DecodeWorkflow(bytes.NewReader(result.Document))
			} else {
				var experiment workflow.Experiment
				experiment, err = DecodeExperiment(bytes.NewReader(result.Document))
				if err == nil {
					got = experiment.Participants[0].Workflow
				}
			}
			want := bad
			want.Edges = want.Edges[:len(want.Edges)-1]
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("repair changed unrelated source: %v", err)
			}
		})
	}
}
