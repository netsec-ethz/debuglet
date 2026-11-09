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

func assistantControl(from, port, to string) workflow.Edge {
	return workflow.Edge{Kind: "control", From: workflow.Endpoint{Node: from, Port: port}, To: workflow.Endpoint{Node: to, Port: "in"}}
}

func assistantDisconnectedScaffold() workflow.Workflow {
	w := sampleWorkflow()
	w.Nodes = append(w.Nodes, workflow.Node{ID: "compare", Block: "comparison"}, workflow.Node{ID: "table", Block: "report_table", Inputs: map[string]any{"title": "Comparison", "columns": []any{"value"}}})
	w.CustomBlocks = []workflow.CustomBlock{{ID: "comparison", Label: "Compare", Inputs: []workflow.Port{}, Outputs: []workflow.Port{{Name: "rows", Type: "any"}}, Code: "return map[string]any{\"rows\": []any{}}, nil"}}
	w.Edges = []workflow.Edge{assistantControl("compare", "next", "table"), {Kind: "data", From: workflow.Endpoint{Node: "compare", Port: "rows"}, To: workflow.Endpoint{Node: "table", Port: "rows"}}}
	return w
}

func TestAssistantActionReachability(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*workflow.Workflow, *workflow.Workflow)
		want string
	}{
		{"new scaffold", func(_, _ *workflow.Workflow) {}, "compare"},
		{"unchanged loose actions", func(old, proposed *workflow.Workflow) { *old = *proposed }, ""},
		{"moved loose action", func(old, proposed *workflow.Workflow) {
			*old = assistantDisconnectedScaffold()
			proposed.Nodes[1].Position = &workflow.Position{X: 100, Y: 200}
			proposed.Nodes[1].Inputs = map[string]any{}
			proposed.CustomBlocks[0].Label = "Clearer label"
			proposed.CustomBlocks[0].Description = "Clearer description"
		}, ""},
		{"changed loose action", func(old, proposed *workflow.Workflow) {
			*old = assistantDisconnectedScaffold()
			proposed.Nodes[2].Inputs["title"] = "New comparison"
		}, "table"},
		{"changed custom implementation", func(old, proposed *workflow.Workflow) {
			*old = assistantDisconnectedScaffold()
			proposed.CustomBlocks[0].Code = "return nil, nil"
		}, "compare"},
		{"formerly reachable", func(old, _ *workflow.Workflow) {
			*old = assistantDisconnectedScaffold()
			old.Edges = append(old.Edges, assistantControl("result", "next", "compare"))
		}, "compare"},
		{"pure nodes and loop branches", func(_, proposed *workflow.Workflow) {
			*proposed = workflow.Workflow{Entry: "loop", Nodes: []workflow.Node{
				{ID: "loop", Block: "repeat"}, {ID: "gate", Block: "if"}, {ID: "left", Block: "emit"}, {ID: "right", Block: "emit"}, {ID: "done", Block: "emit"}, {ID: "value", Block: "add"},
			}, Edges: []workflow.Edge{assistantControl("loop", "body", "gate"), assistantControl("loop", "done", "done"), assistantControl("gate", "true", "left"), assistantControl("gate", "false", "right")}}
		}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			original, proposed := sampleWorkflow(), assistantDisconnectedScaffold()
			test.edit(&original, &proposed)
			before, _ := json.Marshal(original)
			after, _ := json.Marshal(proposed)
			err := assistantValidateReachability("workflow", before, after)
			if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), `"node":"`+test.want+`"`)) {
				t.Fatalf("reachability: %v; want diagnostic for %q", err, test.want)
			}
		})
	}
}

func TestAssistantRepairsDisconnectedActions(t *testing.T) {
	for _, kind := range []string{"workflow", "experiment"} {
		for _, repair := range []bool{true, false} {
			name := kind + "/repeated_rejection"
			if repair {
				name = kind + "/repaired"
			}
			t.Run(name, func(t *testing.T) {
				bad := assistantDisconnectedScaffold()
				wrap := func(w workflow.Workflow) any {
					if kind == "workflow" {
						return w
					}
					return workflow.Experiment{Version: 1, Kind: kind, Name: "Comparison", Channels: []workflow.Channel{}, Participants: []workflow.Participant{{ID: "A", Workflow: w}, {ID: "B", Workflow: sampleWorkflow()}}}
				}
				raw, _ := json.Marshal(wrap(bad))
				if _, err := assistantValidateDocument(kind, raw); err != nil {
					t.Fatalf("scaffold must pass ordinary validation: %v", err)
				}
				request := assistantInput(t, kind, wrap(sampleWorkflow()))
				before := append([]byte(nil), request.Document...)
				var calls atomic.Int32
				client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
					if calls.Add(1) == 1 {
						var document any = assistantWireFixture(t, bad)
						if kind == "experiment" {
							document = map[string]any{"version": 1, "kind": kind, "name": "Comparison", "channels": []workflow.Channel{}, "participants": []any{
								map[string]any{"id": "A", "workflow": document}, map[string]any{"id": "B", "workflow": assistantWireFixture(t, sampleWorkflow())},
							}}
						}
						assistantToolReply(w, map[string]any{"message": "Compare and report.", "document": document})
						return
					}
					var body struct {
						Messages []assistantModelMessage `json:"messages"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					feedback := body.Messages[len(body.Messages)-1].Content
					if !strings.Contains(feedback, "compare") || !strings.Contains(feedback, "table") || !strings.Contains(feedback, "corrected complete compact document") || kind == "experiment" && !strings.Contains(feedback, `"participant":"A"`) {
						t.Errorf("missing scoped reachability or repair base: %s", feedback)
					}
					participant := ""
					if kind == "experiment" {
						participant = "A"
					}
					edits := assistantEdits{}
					if repair {
						edits.Workflows = []assistantWorkflowEdits{{Participant: participant, AddEdges: []workflow.Edge{assistantControl("result", "next", "compare")}}}
					}
					assistantToolReply(w, map[string]any{"message": "Updated comparison.", "edits": edits})
				})
				client.strictSchema = true
				result, err := client.Reply(t.Context(), request)
				if calls.Load() != 2 || !bytes.Equal(before, request.Document) {
					t.Fatal("repair did not preserve original source or use bounded two attempts")
				}
				if !repair {
					if err == nil || len(result.Document) != 0 {
						t.Fatal("unchanged rejected proposal became an allowed original loose node")
					}
					return
				}
				bad.Edges = append(bad.Edges, assistantControl("result", "next", "compare"))
				want, _ := json.Marshal(wrap(bad))
				var gotDocument, wantDocument any
				_ = json.Unmarshal(result.Document, &gotDocument)
				_ = json.Unmarshal(want, &wantDocument)
				if err != nil || !reflect.DeepEqual(gotDocument, wantDocument) {
					t.Fatalf("repair changed unrelated source: %v", err)
				}
			})
		}
	}
}
