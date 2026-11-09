// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func assistantCustomWorkflow() workflow.Workflow {
	return workflow.Workflow{Version: 1, Name: "Custom calculation", Entry: "calculate",
		Nodes: []workflow.Node{{ID: "calculate", Block: "calculation"}}, Edges: []workflow.Edge{},
		CustomBlocks: []workflow.CustomBlock{{ID: "calculation", Label: "Calculate", Outputs: []workflow.Port{{Name: "value", Type: "number"}}, Code: `return map[string]any{"value": float64(42)}, nil`}}}
}

func TestAssistantCompilationChecksCustomOnlyAndPreservesDraft(t *testing.T) {
	for _, kind := range []string{"workflow", "experiment"} {
		for _, custom := range []bool{false, true} {
			for _, fail := range []bool{false, true} {
				original := sampleWorkflow()
				proposal := original
				if custom {
					proposal = assistantCustomWorkflow()
				}
				var doc any = proposal
				if kind == "experiment" {
					doc = workflow.Experiment{Version: 1, Kind: "experiment", Name: "Pair", Participants: []workflow.Participant{{ID: "A", Workflow: proposal}, {ID: "B", Workflow: original}}}
				}
				calls, checks := 0, 0
				client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; assistantProposal(w, doc) })
				input := assistantInput(t, kind, doc)
				before := bytes.Clone(input.Document)
				infrastructure := errors.New("compiler offline")
				result, err := client.ReplyChecked(t.Context(), input, func(ctx context.Context, gotKind string, raw json.RawMessage) (string, error) {
					checks++
					if gotKind != kind || !json.Valid(raw) {
						t.Error("lost document kind or source")
					}
					if fail {
						return "", infrastructure
					}
					return "", nil
				})
				if custom && fail {
					if !errors.Is(err, infrastructure) || len(result.Document) != 0 {
						t.Fatalf("infrastructure failure exposed proposal: %v", err)
					}
				} else if err != nil || len(result.Document) == 0 {
					t.Fatalf("proposal failed: %v", err)
				}
				if calls != 1 || (checks == 1) != custom || !bytes.Equal(input.Document, before) {
					t.Fatal("check bypass, unexpected repair or mutated original")
				}
			}
		}
	}
}

func TestAssistantCompilationRepairIsBounded(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		calls, checks := 0, 0
		client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 2 {
				var request struct {
					Messages []assistantModelMessage `json:"messages"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil || !strings.Contains(request.Messages[len(request.Messages)-1].Content, "undefined: missing") {
					t.Error("missing compiler feedback")
				}
			}
			assistantProposal(w, assistantCustomWorkflow())
		})
		result, err := client.ReplyChecked(t.Context(), assistantInput(t, "workflow", sampleWorkflow()), func(context.Context, string, json.RawMessage) (string, error) {
			checks++
			if fixed && checks == 2 {
				return "", nil
			}
			return "undefined: missing", nil
		})
		if calls != 2 || checks != 2 || (err == nil) != fixed || (len(result.Document) > 0) != fixed {
			t.Fatalf("repair limit/result wrong: calls=%d checks=%d err=%v", calls, checks, err)
		}
	}
}

func TestAssistantCompilationCancellationDoesNotRepair(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; assistantProposal(w, assistantCustomWorkflow()) })
	result, err := client.ReplyChecked(ctx, assistantInput(t, "workflow", sampleWorkflow()), func(checkCtx context.Context, _ string, _ json.RawMessage) (string, error) {
		cancel()
		<-checkCtx.Done()
		return "", checkCtx.Err()
	})
	var failure *AssistantError
	if calls != 1 || len(result.Document) != 0 || !errors.As(err, &failure) || failure.Code != "canceled" {
		t.Fatalf("cancellation lost: %v", err)
	}
}
