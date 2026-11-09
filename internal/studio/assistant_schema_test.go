// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func assistantWireFixture(t *testing.T, wf workflow.Workflow) assistantWireWorkflow {
	t.Helper()
	wire := assistantWireWorkflow{Version: wf.Version, Name: wf.Name, Entry: wf.Entry, Edges: wf.Edges, Groups: wf.Groups}
	ports := func(in []workflow.Port) []assistantWirePort {
		out := make([]assistantWirePort, len(in))
		for i, p := range in {
			value, _ := json.Marshal(p.Default)
			out[i] = assistantWirePort{Name: p.Name, Type: p.Type, Required: p.Required, DefaultJSON: string(value)}
		}
		return out
	}
	for _, b := range wf.CustomBlocks {
		wire.CustomBlocks = append(wire.CustomBlocks, assistantWireBlock{ID: b.ID, Label: b.Label, Description: b.Description, Inputs: ports(b.Inputs), Outputs: ports(b.Outputs), Code: b.Code})
	}
	for _, n := range wf.Nodes {
		inputs := n.Inputs
		if inputs == nil {
			inputs = map[string]any{}
		}
		literal, _ := json.Marshal(inputs)
		node := assistantWireNode{ID: n.ID, Block: n.Block, InputsJSON: string(literal), Position: n.Position}
		for _, block := range wf.CustomBlocks {
			if block.ID == n.Block {
				node.Block, node.CustomBlock = "", n.Block
			}
		}
		wire.Nodes = append(wire.Nodes, node)
	}
	return wire
}

func TestAssistantStrictSchemaUsesClosedObjects(t *testing.T) {
	for _, kind := range []string{"workflow", "experiment"} {
		var walk func(any)
		walk = func(value any) {
			switch node := value.(type) {
			case map[string]any:
				if props, ok := node["properties"].(map[string]any); ok {
					if node["additionalProperties"] != false {
						t.Fatal("strict object allows unknown properties")
					}
					required, ok := node["required"].([]string)
					if !ok || len(required) != len(props) {
						t.Fatal("strict object has optional properties")
					}
					for _, name := range required {
						if _, ok := props[name]; !ok {
							t.Fatal("unknown required property")
						}
					}
				}
				for _, child := range node {
					walk(child)
				}
			case []any:
				for _, child := range node {
					walk(child)
				}
			}
		}
		walk(assistantDocumentSchema(kind))
	}
}

func TestAssistantStrictProposalNormalizesLiteralInputsAndMetadata(t *testing.T) {
	wf := sampleWorkflow()
	wf.Nodes[0].Position = &workflow.Position{X: 20, Y: 40}
	wf.CustomBlocks = []workflow.CustomBlock{{ID: "prepare", Label: "Prepare result", Inputs: []workflow.Port{{Name: "value", Type: "object", Default: map[string]any{"values": []any{true, float64(2)}}}}, Outputs: []workflow.Port{{Name: "value", Type: "object"}}, Code: "return map[string]any{\"value\":inputs[\"value\"]},nil"}}
	wf.CustomBlocks[0].Description = "Pass the object through without changing its fields."
	wf.Nodes[0].Inputs["value"] = map[string]any{"nested": []any{true, float64(3), "literal"}}
	wf.Nodes = append(wf.Nodes, workflow.Node{ID: "pause", Block: "wait", Inputs: map[string]any{"duration_ms": float64(1)}})
	wf.Edges = append(wf.Edges, workflow.Edge{Kind: "control", From: workflow.Endpoint{Node: "result", Port: "next"}, To: workflow.Endpoint{Node: "pause", Port: "in"}})
	wf.Groups = []workflow.Group{{ID: "results", Label: "Results", NodeIDs: []string{"result", "pause"}}}
	client := assistantFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		tool := body["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)
		if tool["strict"] != true || body["parallel_tool_calls"] != false {
			t.Error("strict single-call mode missing")
		}
		choice := body["tool_choice"].(map[string]any)
		if choice["function"].(map[string]any)["name"] != "propose_document" {
			t.Error("tool call not required")
		}
		assistantToolReply(w, map[string]any{"message": "Ready", "action": "", "document": assistantWireFixture(t, wf)})
	})
	client.strictSchema = true
	result, err := client.Reply(t.Context(), assistantInput(t, "workflow", wf))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := DecodeWorkflow(bytes.NewReader(result.Document))
	if err != nil || !reflect.DeepEqual(doc, wf) {
		t.Fatalf("wire conversion changed source: %v", err)
	}
	if bytes.Contains(result.Document, []byte("inputs_json")) {
		t.Fatal("provider wire format reached editor")
	}
}

func TestAssistantStrictClarificationAndCoordinateHaveNoDocument(t *testing.T) {
	for _, action := range []string{"", "coordinate"} {
		client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			assistantToolReply(w, map[string]any{"message": "Which target?", "action": action, "document": nil})
		})
		client.strictSchema = true
		result, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
		if err != nil || result.Action != action || len(result.Document) != 0 {
			t.Fatalf("unexpected clarification: %+v %v", result, err)
		}
	}
}

func TestAssistantStrictWireStillRejectsInvalidGraph(t *testing.T) {
	wf := sampleWorkflow()
	wf.Entry = "missing"
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		assistantToolReply(w, map[string]any{"message": "Ready", "action": "", "document": assistantWireFixture(t, wf)})
	})
	client.strictSchema = true
	result, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
	var classified *AssistantError
	if calls.Load() != 2 || len(result.Document) != 0 || !errors.As(err, &classified) || classified.Code != "invalid_graph" || !errors.Is(err, ErrAssistantInvalidReply) {
		t.Fatalf("invalid graph escaped: %v", err)
	}
}

func TestAssistantClassifiesProviderFailureWithoutBody(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
	}{{401, "provider_auth"}, {403, "provider_auth"}, {429, "provider_rate_limit"}, {500, "provider_unavailable"}} {
		client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("private-fixture-secret"))
		})
		_, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
		var classified *AssistantError
		if !errors.As(err, &classified) || classified.Code != tc.code || classified.ProviderStatus != tc.status || !errors.Is(err, ErrAssistantUnavailable) || strings.Contains(err.Error(), "private-fixture-secret") {
			t.Fatalf("unsafe provider error: %v", err)
		}
	}
}

func TestAssistantTruncationIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"length","message":{"content":"partial"}}]}`))
	})
	_, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
	var classified *AssistantError
	if calls.Load() != 1 || !errors.As(err, &classified) || classified.Code != "output_truncated" {
		t.Fatalf("unexpected truncation handling: %v", err)
	}
}

func TestAssistantRefusesManualGoBeforeProvider(t *testing.T) {
	code := "func run() {}"
	wf := sampleWorkflow()
	wf.GoCode = &code
	for _, kind := range []string{"workflow", "experiment"} {
		var document any = wf
		if kind == "experiment" {
			document = workflow.Experiment{Version: 1, Kind: "experiment", Name: "Manual", Participants: []workflow.Participant{{ID: "A", Workflow: wf}, {ID: "B", Workflow: sampleWorkflow()}}}
		}
		raw, _ := json.Marshal(map[string]any{"kind": kind, "document": document, "message": "Rename it"})
		if _, err := DecodeAssistantRequest(bytes.NewReader(raw)); err == nil {
			t.Fatal("manual Go could be silently replaced")
		}
	}
}

func TestAssistantStrictExperimentRoundTrip(t *testing.T) {
	wf := sampleWorkflow()
	native := workflow.Experiment{Version: 1, Kind: "experiment", Name: "Pair", Participants: []workflow.Participant{{ID: "A", Label: "First", Workflow: wf}, {ID: "B", Label: "Second", Workflow: wf}}, Channels: []workflow.Channel{{ID: "result", From: "A", To: "B", Type: "object"}}}
	raw, _ := json.Marshal(map[string]any{"version": native.Version, "kind": native.Kind, "name": native.Name, "channels": native.Channels, "participants": []any{map[string]any{"id": "A", "label": "First", "workflow": assistantWireFixture(t, wf)}, map[string]any{"id": "B", "label": "Second", "workflow": assistantWireFixture(t, wf)}}})
	decoded, err := assistantDecodeWireDocument("experiment", raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc workflow.Experiment
	if err := json.Unmarshal(decoded, &doc); err != nil || !reflect.DeepEqual(doc, native) {
		t.Fatalf("experiment wire changed graph: %v", err)
	}
	schema := assistantDocumentSchema("experiment")
	participants := schema["properties"].(map[string]any)["document"].(map[string]any)["properties"].(map[string]any)["participants"].(map[string]any)
	graph := participants["items"].(map[string]any)["properties"].(map[string]any)["workflow"].(map[string]any)
	if graph["$ref"] == "#/$defs/compact_workflow" {
		graph = schema["$defs"].(map[string]any)["compact_workflow"].(map[string]any)
	}
	if graph["type"] != "object" {
		t.Fatal("participant workflow must not be nullable")
	}
	channels := schema["properties"].(map[string]any)["document"].(map[string]any)["properties"].(map[string]any)["channels"].(map[string]any)
	channel := channels["items"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []string{"type", "response_type"} {
		values, ok := channel[field].(map[string]any)["enum"].([]string)
		if !ok || len(values) == 0 {
			t.Fatal("channel types are unconstrained")
		}
		for _, value := range values {
			test := native
			test.Channels = []workflow.Channel{{ID: "test", From: "A", To: "B", Type: "object"}}
			if field == "type" {
				test.Channels[0].Type = value
			} else {
				test.Channels[0].ResponseType = value
			}
			if ds := workflow.ValidateExperiment(test); len(ds) != 0 {
				t.Fatalf("schema channel type %q does not validate: %+v", value, ds)
			}
		}
	}
}

func TestAssistantExpiredDeadlineHasDistinctReason(t *testing.T) {
	client := assistantFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("expired request reached provider") })
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := client.Reply(ctx, assistantInput(t, "workflow", sampleWorkflow()))
	var classified *AssistantError
	if !errors.As(err, &classified) || classified.Code != "deadline_exceeded" || !errors.Is(err, ErrAssistantTimeout) {
		t.Fatalf("unexpected deadline error: %v", err)
	}
}
