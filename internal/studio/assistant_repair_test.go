// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAssistantRepairModeMatchesFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		document string
		edits    bool
		compile  bool
		complete bool
	}{
		{"compact binding", strings.Replace(compactBranchFixture, `"condition.value"`, `"broken"`, 1), false, false, true},
		{"graph reference", strings.Replace(compactBranchFixture, `"condition.value"`, `"missing.value"`, 1), false, false, true},
		{"disconnected actions", strings.Replace(compactBranchFixture, `"true":"loop"`, `"true":"end"`, 1), false, false, true},
		{"scoped edits", "", true, false, false},
		{"compiler only", "", false, true, false},
	} {
		for _, fixed := range []bool{false, true} {
			name := test.name + "/rejected_twice"
			if fixed {
				name = test.name + "/corrected"
			}
			t.Run(name, func(t *testing.T) {
				proposal := map[string]any{"message": "Proposed experiment.", "document": json.RawMessage(test.document)}
				if test.edits {
					proposal = map[string]any{"message": "Updated result.", "edits": assistantEdits{Workflows: []assistantWorkflowEdits{{UpsertNodes: []assistantWireNode{{ID: "result", Block: "report_metric", InputsJSON: `{}`}}}}}}
				}
				if test.compile {
					proposal["document"] = assistantWireFixture(t, assistantCustomWorkflow())
				}
				calls := 0
				client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
					calls++
					if calls == 2 {
						var body struct {
							Messages []assistantModelMessage `json:"messages"`
						}
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
							return
						}
						feedback := body.Messages[len(body.Messages)-1].Content
						if test.complete {
							if !strings.Contains(feedback, "complete compact document with edits null") || !strings.Contains(feedback, "Preserve all requested measurements and report actions") || strings.Contains(feedback, "Return edits") {
								t.Errorf("structural repair changed representation or dropped actions: %s", feedback)
							}
						} else if !strings.Contains(feedback, "Edits now target the rejected proposal") || !strings.Contains(feedback, "Return edits for the failing parts") || strings.Contains(feedback, "with edits null") {
							t.Errorf("scoped correction unnecessarily requested a full rewrite: %s", feedback)
						}
						if fixed {
							assistantToolReply(w, map[string]any{"message": "Corrected experiment.", "document": json.RawMessage(compactBranchFixture)})
							return
						}
					}
					assistantToolReply(w, proposal)
				})
				client.strictSchema = true
				input := assistantInput(t, "workflow", sampleWorkflow())
				before := bytes.Clone(input.Document)
				result, err := client.ReplyChecked(t.Context(), input, func(context.Context, string, json.RawMessage) (string, error) {
					return "undefined: missing", nil
				})
				if calls != 2 || (err == nil) != fixed || (len(result.Document) > 0) != fixed || !bytes.Equal(input.Document, before) {
					t.Fatalf("wrong repair result or mutated draft: calls=%d fixed=%t err=%v", calls, fixed, err)
				}
			})
		}
	}
}
