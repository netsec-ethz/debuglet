// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func responsesFixture(t *testing.T, handler http.HandlerFunc) *Assistant {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewAssistant(AssistantConfig{Endpoint: server.URL + "/v1/responses", Model: "fixture-model", APIKey: "fixture-secret", ReasoningEffort: "high"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func responsesOutput(t *testing.T, proposal any) []json.RawMessage {
	t.Helper()
	arguments, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	call, err := json.Marshal(map[string]any{"type": "function_call", "id": "fc_item_id", "call_id": "call_result_id", "status": "completed", "name": "propose_document", "arguments": string(arguments)})
	if err != nil {
		t.Fatal(err)
	}
	return []json.RawMessage{json.RawMessage(`{"type":"reasoning","id":"rs_item","summary":[],"encrypted_content":"opaque-private-state"}`), call}
}

func TestAssistantResponsesRequestAndProposal(t *testing.T) {
	wf := sampleWorkflow()
	wf.Name = "Readable result"
	client := responsesFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer fixture-secret" {
			t.Error("unexpected provider request")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["store"] != false || body["stream"] != false || body["parallel_tool_calls"] != false || body["max_output_tokens"] != float64(16384) {
			t.Error("missing bounded stateless Responses settings")
		}
		if body["reasoning"].(map[string]any)["effort"] != "high" || !reflect.DeepEqual(body["include"], []any{"reasoning.encrypted_content"}) {
			t.Error("reasoning settings missing")
		}
		for _, name := range []string{"messages", "reasoning_effort", "max_tokens", "max_completion_tokens", "previous_response_id"} {
			if _, present := body[name]; present {
				t.Errorf("unexpected Responses field %s", name)
			}
		}
		tool := body["tools"].([]any)[0].(map[string]any)
		if tool["type"] != "function" || tool["name"] != "propose_document" || tool["strict"] != true || tool["function"] != nil {
			t.Error("Responses function schema was not flattened")
		}
		wantSchema, _ := json.Marshal(assistantDocumentSchema("workflow"))
		gotSchema, _ := json.Marshal(tool["parameters"])
		if !bytes.Equal(wantSchema, gotSchema) {
			t.Error("Responses changed the proposal schema")
		}
		choice := body["tool_choice"].(map[string]any)
		if choice["type"] != "function" || choice["name"] != "propose_document" {
			t.Error("named function was not required")
		}
		input := body["input"].([]any)
		if len(input) != 2 || input[0].(map[string]any)["role"] != "system" || input[1].(map[string]any)["role"] != "user" {
			t.Error("prompt messages were not preserved")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": responsesOutput(t, map[string]any{"message": "Ready", "action": "", "document": assistantWireFixture(t, wf)})})
	})
	result, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := DecodeWorkflow(bytes.NewReader(result.Document))
	if err != nil || doc.Name != wf.Name {
		t.Fatalf("proposal lost: %v", err)
	}
	public, _ := json.Marshal(result)
	if bytes.Contains(public, []byte("opaque-private")) || bytes.Contains(public, []byte("rs_item")) {
		t.Fatal("private reasoning reached the browser")
	}
}

func TestAssistantResponsesRepairReplaysReasoningAndCall(t *testing.T) {
	wf := sampleWorkflow()
	invalid := assistantWireFixture(t, wf)
	invalid.Entry = "missing"
	first := responsesOutput(t, map[string]any{"message": "Ready", "action": "", "document": invalid})
	var calls atomic.Int32
	client := responsesFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 2 {
			var body struct {
				Input []json.RawMessage `json:"input"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Input) != 5 {
				t.Fatalf("repair input has %d items", len(body.Input))
			}
			for i, original := range first {
				var before, after any
				_ = json.Unmarshal(original, &before)
				_ = json.Unmarshal(body.Input[i+2], &after)
				if !reflect.DeepEqual(before, after) {
					t.Error("repair altered provider reasoning or function-call item")
				}
			}
			var feedback map[string]any
			_ = json.Unmarshal(body.Input[4], &feedback)
			if feedback["type"] != "function_call_output" || feedback["call_id"] != "call_result_id" || !strings.Contains(feedback["output"].(string), "Diagnostics:") {
				t.Error("repair did not target the function call with validation feedback")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": responsesOutput(t, map[string]any{"message": "Fixed", "action": "", "document": assistantWireFixture(t, wf)})})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": first})
	})
	result, err := client.Reply(t.Context(), assistantInput(t, "workflow", wf))
	if err != nil || len(result.Document) == 0 || calls.Load() != 2 {
		t.Fatalf("repair failed: calls=%d err=%v", calls.Load(), err)
	}
}

func TestAssistantResponsesRejectsIncompleteAndInvalidOutputs(t *testing.T) {
	for _, tc := range []struct {
		name, response, code string
	}{
		{"truncated", `{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}`, "output_truncated"},
		{"filtered", `{"status":"incomplete","incomplete_details":{"reason":"content_filter"}}`, "invalid_response"},
		{"failed", `{"status":"failed","error":{"message":"private-provider-error"}}`, "provider_unavailable"},
		{"pending", `{"status":"in_progress","output":[]}`, "invalid_response"},
		{"refused", `{"status":"completed","output":[{"type":"message","content":[{"type":"refusal","refusal":"private-provider-error"}]}]}`, "invalid_response"},
		{"no_call", `{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"I will do it"}]}]}`, "invalid_response"},
		{"wrong_tool", `{"status":"completed","output":[{"type":"function_call","name":"execute","call_id":"c","arguments":"{}"}]}`, "invalid_response"},
		{"missing_call_id", `{"status":"completed","output":[{"type":"function_call","name":"propose_document","id":"not-the-call-id","arguments":"{}"}]}`, "invalid_response"},
		{"incomplete_call", `{"status":"completed","output":[{"type":"function_call","name":"propose_document","call_id":"c","status":"in_progress","arguments":"{}"}]}`, "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := responsesFixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.response)) })
			result, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
			var failure *AssistantError
			if !errors.As(err, &failure) || failure.Code != tc.code || len(result.Document) != 0 || strings.Contains(err.Error(), "private-provider-error") {
				t.Fatalf("unsafe result: %v", err)
			}
		})
	}
}
