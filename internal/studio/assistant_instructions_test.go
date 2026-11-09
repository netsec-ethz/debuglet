// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAssistantUsesOneAuthoringEncoding(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := "native"
		if strict {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Messages []assistantModelMessage `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				if len(request.Messages) < 2 {
					t.Fatal("missing authoring context")
				}
				instructions := request.Messages[0].Content
				if strings.Contains(instructions, assistantLegacyInstructions) == strict || strings.Contains(instructions, assistantStrictInstructions) != strict {
					t.Error("provider received conflicting or missing response encodings")
				}
				if !strings.Contains(instructions, assistantInstructions) || !strings.Contains(request.Messages[len(request.Messages)-1].Content, `"document":`) {
					t.Error("missing shared semantics or current editor document")
				}
				reply := map[string]any{"message": "Which target?"}
				if strict {
					reply["action"] = ""
					reply["document"] = nil
				}
				assistantToolReply(w, reply)
			})
			client.strictSchema = strict
			result, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
			if err != nil || len(result.Document) != 0 {
				t.Fatalf("clarification failed: %v", err)
			}
		})
	}
}
