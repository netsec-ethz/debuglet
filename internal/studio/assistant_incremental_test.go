// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func TestAssistantCorrectionEditsRejectedCandidate(t *testing.T) {
	original := sampleWorkflow()
	candidate := sampleWorkflow()
	candidate.Name = "Wait then report"
	candidate.Entry = "missing"
	candidate.Nodes = append(candidate.Nodes, workflow.Node{ID: "pause", Block: "wait", Inputs: map[string]any{"duration_ms": 1}})
	candidate.Edges = append(candidate.Edges, workflow.Edge{Kind: "control", From: workflow.Endpoint{Node: "pause", Port: "next"}, To: workflow.Endpoint{Node: "result", Port: "in"}})
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			assistantToolReply(w, map[string]any{"message": "Ready", "document": assistantWireFixture(t, candidate)})
			return
		}
		var body struct { Messages []assistantModelMessage `json:"messages"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil { t.Fatal(err) }
		if !strings.Contains(body.Messages[len(body.Messages)-1].Content, "target the rejected proposal") {
			t.Error("correction base is ambiguous")
		}
		entry := "pause"
		assistantToolReply(w, map[string]any{"message": "Corrected entry", "edits": assistantEdits{Workflows: []assistantWorkflowEdits{{Entry: &entry}}}})
	})
	client.strictSchema = true
	result, err := client.Reply(t.Context(), assistantInput(t, "workflow", original))
	if err != nil { t.Fatal(err) }
	doc, err := DecodeWorkflow(bytes.NewReader(result.Document))
	if err != nil || doc.Name != candidate.Name || doc.Entry != "pause" || len(doc.Nodes) != 2 || len(doc.Edges) != 1 {
		t.Fatalf("repair discarded proposed source: %+v %v", doc, err)
	}
	if original.Entry != "result" || len(original.Nodes) != 1 { t.Fatal("original mutated") }
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, []byte(`"edits"`)) { t.Fatal("internal edits escaped into public response") }
}

func TestAssistantRejectsAmbiguousDocumentAndEdits(t *testing.T) {
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		assistantToolReply(w, map[string]any{"message": "Ready", "document": assistantWireFixture(t, sampleWorkflow()), "edits": assistantEdits{}})
	})
	client.strictSchema = true
	result, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
	if !errors.Is(err, ErrAssistantInvalidReply) || len(result.Document) != 0 { t.Fatalf("ambiguous edit applied: %v", err) }
}

func TestAssistantBuiltInChoicesAndExplicitCustomReferences(t *testing.T) {
	schema := assistantDocumentSchema("workflow")
	graph := schema["properties"].(map[string]any)["document"].(map[string]any)
	nodes := graph["properties"].(map[string]any)["nodes"].(map[string]any)
	variants := nodes["items"].(map[string]any)["anyOf"].([]any)
	choices := variants[0].(map[string]any)["properties"].(map[string]any)["block"].(map[string]any)["enum"].([]string)
	if len(choices) != len(workflow.Catalog()) { t.Fatal("schema catalog drift") }
	for i, block := range workflow.Catalog() { if choices[i] != block.ID { t.Fatal("catalog order changed") } }
	for _, node := range []assistantWireNode{
		{ID:"bad", Block:"invented", InputsJSON:"{}"},
		{ID:"bad", Block:"wait", CustomBlock:"helper", InputsJSON:"{}"},
		{ID:"bad", CustomBlock:"wait", InputsJSON:"{}"},
	} {
		if _, err := node.document(); err == nil { t.Fatal("invalid block choice accepted") }
	}
	wf := sampleWorkflow()
	wf.Nodes[0].Block = "helper"
	wf.Nodes[0].Inputs = map[string]any{}
	wf.CustomBlocks = []workflow.CustomBlock{{ID:"helper", Label:"Helper", Code:"return map[string]any{}, nil"}}
	raw, _ := json.Marshal(assistantWireFixture(t, wf))
	decoded, err := assistantDecodeWireDocument("workflow", raw)
	if err != nil { t.Fatal(err) }
	if _, err := assistantValidateDocument("workflow", decoded); err != nil { t.Fatal(err) }
	wf.CustomBlocks = nil
	// Decoding preserves an explicit custom reference; semantic validation still
	// requires its definition and checks the custom block's implementation.
	wire := assistantWireWorkflow{Version:1, Name:"Invalid helper", Entry:"result", Nodes:[]assistantWireNode{{ID:"result", CustomBlock:"helper", InputsJSON:"{}"}}}
	raw, _ = json.Marshal(wire)
	decoded, err = assistantDecodeWireDocument("workflow", raw)
	if err != nil { t.Fatal(err) }
	if _, err := assistantValidateDocument("workflow", decoded); err == nil { t.Fatal("undeclared helper accepted") }
}
