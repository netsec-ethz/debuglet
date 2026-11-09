// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func TestAssistantCodeOfferRequiresAChoice(t *testing.T) {
	for _, kind := range []string{"workflow", "experiment"} {
		var doc any = sampleWorkflow()
		if kind == "experiment" {
			doc = workflow.Experiment{Version: 1, Kind: "experiment", Name: "Pair", Participants: []workflow.Participant{{ID: "A", Workflow: sampleWorkflow()}, {ID: "B", Workflow: sampleWorkflow()}}}
		}
		client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			assistantToolReply(w, map[string]any{"message": "Persistent socket handling would be clearer in Go. Use Go for this program?", "action": "code"})
		})
		reply, err := client.Reply(t.Context(), assistantInput(t, kind, doc))
		if err != nil || reply.Action != "code" || len(reply.Document) != 0 {
			t.Fatalf("invalid code offer: %+v %v", reply, err)
		}
	}
}

func TestAssistantGoClarificationRequiresExplicitOutcome(t *testing.T) {
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			assistantToolReply(w, map[string]any{"message": "I will write the function.", "action": "", "code": nil})
			return
		}
		assistantToolReply(w, map[string]any{"message": "Which endpoint should the function contact?", "action": "clarify", "code": nil})
	})
	client.strictSchema = true
	request := assistantInput(t, "workflow", sampleWorkflow())
	request.AllowCode = true
	reply, err := client.Reply(t.Context(), request)
	if err != nil || calls.Load() != 2 || reply.Action != "" || len(reply.Document) != 0 || reply.Message != "Which endpoint should the function contact?" {
		t.Fatalf("invalid clarification outcome: %+v %v", reply, err)
	}
}

func TestAssistantRejectsUnapprovedGoFromBothResponseFormats(t *testing.T) {
	for _, mode := range []string{"native", "code"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				code := "func run0() error { return nil }"
				if mode == "code" {
					assistantToolReply(w, map[string]any{"message": "Switched", "code": []assistantCodeEdit{{GoCode: code}}})
					return
				}
				doc := sampleWorkflow()
				doc.GoCode = &code
				assistantProposal(w, doc)
			})
			reply, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
			if err == nil || len(reply.Document) != 0 || calls.Load() != 2 {
				t.Fatalf("unapproved code accepted: %+v %v", reply, err)
			}
		})
	}
}

func TestAssistantOptedGoPreservesVisualSourceAndCompiles(t *testing.T) {
	original := sampleWorkflow()
	original.Nodes[0].Position = &workflow.Position{X: 42, Y: 75}
	code := "func run0() error { return runtime.Record(\"result\",\"emit\",map[string]any{\"value\": float64(19)}) }"
	client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Messages []assistantModelMessage `json:"messages"`
			Tools    []map[string]any        `json:"tools"`
		}
		if json.NewDecoder(r.Body).Decode(&payload) != nil || !strings.Contains(payload.Messages[1].Content, "code_context") || !strings.Contains(payload.Messages[1].Content, "func run0() error") {
			t.Error("missing actual source context")
		}
		if strings.Contains(payload.Messages[0].Content, "Available blocks:") {
			t.Error("Go mode needlessly carries entire block catalog")
		}
		assistantToolReply(w, map[string]any{"message": "Edited functions; saved blocks are preserved.", "code": []assistantCodeEdit{{GoCode: code}}})
	})
	client.strictSchema = true
	input := assistantInput(t, "workflow", original)
	input.AllowCode = true
	var stages []string
	checks := 0
	reply, err := client.ReplyObserved(t.Context(), input, func(_ context.Context, kind string, raw json.RawMessage) (string, error) {
		checks++
		got, e := DecodeWorkflow(bytes.NewReader(raw))
		if e != nil || kind != "workflow" || got.GoCode == nil || *got.GoCode != code {
			t.Fatalf("wrong compiler input %v", e)
		}
		got.GoCode = nil
		if !reflect.DeepEqual(got, original) {
			t.Fatal("Go replacement changed saved visual graph")
		}
		return "", nil
	}, func(stage string) error { stages = append(stages, stage); return nil })
	if err != nil || checks != 1 || !assistantHasGoCode("workflow", reply.Document) || !reflect.DeepEqual(stages, []string{"generating", "validating", "compiling"}) {
		t.Fatalf("bad Go response: stages=%v checks=%d %v", stages, checks, err)
	}
	if original.GoCode != nil {
		t.Fatal("request graph mutated")
	}
}

func TestAssistantGoModeRejectsVisualReplacementAndNeedsCompiler(t *testing.T) {
	for _, mode := range []string{"visual-rewrite", "no-compiler"} {
		t.Run(mode, func(t *testing.T) {
			client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				if mode == "visual-rewrite" {
					assistantProposal(w, sampleWorkflow())
					return
				}
				assistantToolReply(w, map[string]any{"message": "Done", "code": []assistantCodeEdit{{GoCode: "func run0() error { return nil }"}}})
			})
			input := assistantInput(t, "workflow", sampleWorkflow())
			input.AllowCode = true
			if reply, err := client.Reply(t.Context(), input); err == nil || len(reply.Document) != 0 {
				t.Fatal("uncompiled or rewritten Go proposal accepted")
			}
		})
	}
}

func TestAssistantGoRepairUsesSameSavedGraph(t *testing.T) {
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			assistantToolReply(w, map[string]any{"message": "First", "code": []assistantCodeEdit{{GoCode: "func run0() error { return unknownName }"}}})
			return
		}
		assistantToolReply(w, map[string]any{"message": "Corrected", "code": []assistantCodeEdit{{GoCode: "func run0() error { return nil }"}}})
	})
	input := assistantInput(t, "workflow", sampleWorkflow())
	input.AllowCode = true
	checks := 0
	var stages []string
	_, err := client.ReplyObserved(t.Context(), input, func(_ context.Context, _ string, raw json.RawMessage) (string, error) {
		checks++
		if checks == 1 {
			return "undefined: unknownName", nil
		}
		return "", nil
	}, func(s string) error { stages = append(stages, s); return nil })
	if err != nil || checks != 2 || calls.Load() != 2 || !reflect.DeepEqual(stages, []string{"generating", "validating", "compiling", "repairing", "validating", "compiling"}) {
		t.Fatalf("repair stages: %v, %v", stages, err)
	}
}

func TestAssistantGoContextAndEditsForParticipantsAndBlankPrograms(t *testing.T) {
	blank := workflow.Workflow{Version: 1, Name: "Empty", Nodes: []workflow.Node{}, Edges: []workflow.Edge{}}
	e := workflow.Experiment{Version: 1, Kind: "experiment", Name: "Pair", Participants: []workflow.Participant{{ID: "A", Workflow: blank}, {ID: "B", Workflow: sampleWorkflow()}}, Channels: []workflow.Channel{{ID: "message", From: "A", To: "B", Type: "string"}}}
	raw, _ := json.Marshal(e)
	prepared, contexts, err := assistantPrepareCode("experiment", raw)
	if err != nil || len(contexts) != 2 || contexts[0].Participant != "A" || !strings.Contains(contexts[0].Source, "guest.JoinExperiment") {
		t.Fatalf("bad coordinated context: %v", err)
	}
	updated, err := assistantApplyCode("experiment", prepared, []assistantCodeEdit{{Participant: "A", GoCode: "func run0() error { return nil }"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeExperiment(bytes.NewReader(updated))
	if err != nil || got.Participants[0].Workflow.GoCode == nil || got.Participants[1].Workflow.GoCode != nil || !reflect.DeepEqual(got.Participants[1].Workflow, e.Participants[1].Workflow) || !reflect.DeepEqual(got.Channels, e.Channels) {
		t.Fatalf("saved programs/channels changed: %v", err)
	}
	for _, edits := range [][]assistantCodeEdit{{{Participant: "missing", GoCode: "func run0() error{return nil}"}}, {{Participant: "A", GoCode: "x"}, {Participant: "A", GoCode: "x"}}} {
		if _, err := assistantApplyCode("experiment", prepared, edits); err == nil {
			t.Fatal("invalid participant code edit accepted")
		}
	}
}

func TestAssistantObservedStopsBeforeProviderOnCanceledObserver(t *testing.T) {
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); assistantProposal(w, sampleWorkflow()) })
	_, err := client.ReplyObserved(t.Context(), assistantInput(t, "workflow", sampleWorkflow()), nil, func(string) error { return context.Canceled })
	if !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatal("observer cancellation still generated")
	}
}

func TestAssistantEnforcesTenCardsAtEachLevel(t *testing.T) {
	w := sampleWorkflow()
	w.Nodes = nil
	w.Edges = nil
	w.Entry = "n0"
	for i := 0; i < 11; i++ {
		id := fmt.Sprintf("n%d", i)
		w.Nodes = append(w.Nodes, workflow.Node{ID: id, Block: "emit", Inputs: map[string]any{"name": id, "value": float64(i)}})
		if i > 0 {
			w.Edges = append(w.Edges, workflow.Edge{Kind: "control", From: workflow.Endpoint{Node: fmt.Sprintf("n%d", i-1), Port: "next"}, To: workflow.Endpoint{Node: id, Port: "in"}})
		}
	}
	var calls atomic.Int32
	client := assistantFixture(t, func(rw http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			w.Groups = []workflow.Group{{ID: "stage", Label: "First observations", NodeIDs: []string{"n0", "n1"}}}
		}
		assistantProposal(rw, w)
	})
	reply, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
	if err != nil || calls.Load() != 2 || len(reply.Document) == 0 {
		t.Fatalf("presentation repair failed: %v", err)
	}
	decoded, _ := DecodeWorkflow(bytes.NewReader(reply.Document))
	if len(decoded.Nodes) != 11 || len(decoded.Edges) != 10 || len(decoded.Groups) != 1 {
		t.Fatal("repair dropped measurements")
	}
}

func TestAssistantExistingGoNeedsOptInBeforeAnyProviderCall(t *testing.T) {
	code := "func run0() error { return nil }"
	doc := sampleWorkflow()
	doc.GoCode = &code
	raw, _ := json.Marshal(doc)
	request := AssistantRequest{Kind: "workflow", Document: raw, Message: "change the result"}
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); assistantProposal(w, sampleWorkflow()) })
	if _, err := client.Reply(t.Context(), request); err == nil || calls.Load() != 0 {
		t.Fatal("existing Go silently replaced by blocks")
	}
	encoded, _ := json.Marshal(request)
	if _, err := DecodeAssistantRequest(bytes.NewReader(encoded)); err == nil {
		t.Fatal("HTTP request accepted without consent")
	}
	request.AllowCode = true
	encoded, _ = json.Marshal(request)
	if _, err := DecodeAssistantRequest(bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
}

func TestAssistantGoRepairRetainsOtherParticipantEdits(t *testing.T) {
	e := workflow.Experiment{Version: 1, Kind: "experiment", Name: "Pair", Channels: []workflow.Channel{}, Participants: []workflow.Participant{{ID: "A", Workflow: sampleWorkflow()}, {ID: "B", Workflow: sampleWorkflow()}}}
	goodA := "func run0() error { return runtime.Record(\"result\",\"emit\",map[string]any{\"value\":19}) }"
	goodB := "func run0() error { return nil }"
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		edits := []assistantCodeEdit{{Participant: "A", GoCode: goodA}, {Participant: "B", GoCode: "func run0() error { return missing }"}}
		if calls.Add(1) > 1 {
			edits = []assistantCodeEdit{{Participant: "B", GoCode: goodB}}
		}
		assistantToolReply(w, map[string]any{"message": "Updated functions", "code": edits})
	})
	input := assistantInput(t, "experiment", e)
	input.AllowCode = true
	checks := 0
	reply, err := client.ReplyChecked(t.Context(), input, func(_ context.Context, _ string, raw json.RawMessage) (string, error) {
		checks++
		got, err := DecodeExperiment(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if got.Participants[0].Workflow.GoCode == nil || *got.Participants[0].Workflow.GoCode != goodA {
			t.Fatal("repair lost valid participant A edit")
		}
		if checks == 1 {
			return "participant B: undefined missing", nil
		}
		return "", nil
	})
	if err != nil || checks != 2 {
		t.Fatalf("repair failed: %v", err)
	}
	got, err := DecodeExperiment(bytes.NewReader(reply.Document))
	if err != nil || got.Participants[1].Workflow.GoCode == nil || *got.Participants[1].Workflow.GoCode != goodB {
		t.Fatalf("B not repaired: %v", err)
	}
}
