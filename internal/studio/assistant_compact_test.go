// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

const compactBranchFixture = `{"format":"compact","version":1,"name":"Branch and repeat","entry":"branch","nodes":[
 {"id":"condition","block":"not","inputs":{"value":false},"control":{},"position":null},
 {"id":"branch","block":"if","inputs":{"condition":{"from":"condition.value"}},"control":{"true":"loop","false":"end"},"position":{"x":12,"y":34}},
 {"id":"loop","block":"repeat","inputs":{"count":2},"control":{"body":"sample","done":"end"},"position":null},
 {"id":"sample","block":"emit","inputs":{"name":"sample","value":{"json":"{\"from\":\"literal.not_a_wire\",\"empty\":[],\"zero\":0,\"flag\":false}"}},"control":{"next":null},"position":null},
 {"id":"end","block":"emit","inputs":{"name":"done","value":{"from":"condition.value"}},"control":{"next":null},"position":null}],
 "custom_blocks":[],"groups":[{"id":"sampling","label":"Sampling","node_ids":["loop","sample"],"position":null}]}`

func TestAssistantCompactPreservesExplicitControlAndLiterals(t *testing.T) {
	raw, err := assistantDecodeWireDocument("workflow", []byte(compactBranchFixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assistantValidateDocument("workflow", raw); err != nil {
		t.Fatal(err)
	}
	var got workflow.Workflow
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	wantEdges := []workflow.Edge{
		{Kind: "data", From: workflow.Endpoint{Node: "condition", Port: "value"}, To: workflow.Endpoint{Node: "branch", Port: "condition"}},
		{Kind: "control", From: workflow.Endpoint{Node: "branch", Port: "true"}, To: workflow.Endpoint{Node: "loop", Port: "in"}},
		{Kind: "control", From: workflow.Endpoint{Node: "branch", Port: "false"}, To: workflow.Endpoint{Node: "end", Port: "in"}},
		{Kind: "control", From: workflow.Endpoint{Node: "loop", Port: "body"}, To: workflow.Endpoint{Node: "sample", Port: "in"}},
		{Kind: "control", From: workflow.Endpoint{Node: "loop", Port: "done"}, To: workflow.Endpoint{Node: "end", Port: "in"}},
		{Kind: "data", From: workflow.Endpoint{Node: "condition", Port: "value"}, To: workflow.Endpoint{Node: "end", Port: "value"}},
	}
	if !reflect.DeepEqual(got.Edges, wantEdges) || got.Nodes[0].Inputs["value"] != false {
		t.Fatalf("changed explicit control or false literal: %+v", got)
	}
	wantLiteral := map[string]any{"from": "literal.not_a_wire", "empty": []any{}, "zero": float64(0), "flag": false}
	if !reflect.DeepEqual(got.Nodes[3].Inputs["value"], wantLiteral) || got.Nodes[1].Position.X != 12 || len(got.Groups) != 1 {
		t.Fatal("lost literal, position or grouping")
	}
	for _, marker := range []string{`"format":`, `"control":`, `"inputs_json":`} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("wire field %s escaped to editor", marker)
		}
	}
}

func TestAssistantCompactDefaultsAndRequiredInputs(t *testing.T) {
	base := `{"format":"compact","version":1,"name":"Connect","entry":"tcp","nodes":[{"id":"tcp","block":"tcp_connect","inputs":%s,"control":{"next":null}}],"custom_blocks":[],"groups":[]}`
	for _, tc := range []struct {
		input string
		valid bool
	}{
		{`{"target":"example.org:443","timeout_ms":null}`, true},
		{`{"target":"example.org:443"}`, true},
		{`{"target":null}`, false}, {`{}`, false},
		{`{"target":"example.org:443","invented":1}`, false},
		{`{"target":{"from":"endpoint.target","json":"\"unused\""}}`, false},
		{`{"target":{"from":"endpoint.target.more"}}`, false},
		{`{"target":{"from":"endpoint"}}`, false},
	} {
		raw, err := assistantDecodeWireDocument("workflow", []byte(fmt.Sprintf(base, tc.input)))
		if (err == nil) != tc.valid {
			t.Fatalf("input %s: %v", tc.input, err)
		}
		if tc.valid {
			var doc workflow.Workflow
			_ = json.Unmarshal(raw, &doc)
			if _, exists := doc.Nodes[0].Inputs["timeout_ms"]; exists {
				t.Fatal("default omission became a literal null")
			}
		}
	}
	for _, input := range []string{`false`, `0`, `""`, `{"json":"null"}`, `{"json":"[]"}`} {
		text := `{"format":"compact","version":1,"name":"Literal","entry":"e","nodes":[{"id":"e","block":"emit","inputs":{"name":"result","value":` + input + `},"control":{"next":null}}]}`
		raw, err := assistantDecodeWireDocument("workflow", []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		var doc workflow.Workflow
		_ = json.Unmarshal(raw, &doc)
		if _, exists := doc.Nodes[0].Inputs["value"]; !exists {
			t.Fatalf("lost literal %s", input)
		}
	}
}

func TestAssistantCompactCustomBlocksAndMixedFormats(t *testing.T) {
	const custom = `{"format":"compact","version":1,"name":"Custom","entry":"prepare","nodes":[{"id":"prepare","custom_block":"identity","inputs":[{"port":"value","value":false}],"control":{"next":"show"}},{"id":"show","block":"emit","inputs":{"name":"result","value":{"from":"prepare.value"}},"control":{"next":null}}],"custom_blocks":[{"id":"identity","label":"Identity","description":"Keep the supplied value.","inputs":[{"name":"value","type":"boolean","required":true,"default_json":"null"}],"outputs":[{"name":"value","type":"boolean","required":false,"default_json":"null"}],"code":"return map[string]any{\"value\":inputs[\"value\"]},nil"}]} `
	raw, err := assistantDecodeWireDocument("workflow", []byte(custom))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assistantValidateDocument("workflow", raw); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.Replace(custom, `"inputs":[{"port":"value","value":false}]`, `"inputs":[{"port":"value","value":false},{"port":"value","value":true}]`, 1),
		strings.Replace(custom, `"inputs":[{"port":"value","value":false}]`, `"inputs":[]`, 1),
		strings.Replace(custom, `"custom_block":"identity"`, `"custom_block":"unknown"`, 1),
		strings.Replace(custom, `"format":"compact"`, `"format":"compact","edges":[]`, 1),
		strings.Replace(custom, `"format":"compact"`, `"format":"invented"`, 1),
		strings.Replace(custom, `"custom_block":"identity"`, `"custom_block":"identity","inputs_json":"{}"`, 1),
		strings.Replace(compactBranchFixture, `"control":{}`, `"control":{"next":"branch"}`, 1),
	} {
		if _, err := assistantDecodeWireDocument("workflow", []byte(invalid)); err == nil {
			t.Fatalf("invalid compact source accepted: %s", invalid)
		}
	}
	legacy := assistantWireNode{ID: "wait", Block: "wait", InputsJSON: `{"duration_ms":1}`, Inputs: json.RawMessage(`{"duration_ms":2}`)}
	if _, err := legacy.document(); err == nil {
		t.Fatal("legacy edit silently ignored compact fields")
	}
}

func TestAssistantCompactProposalAndRepairUseCanonicalBase(t *testing.T) {
	proposal := strings.Replace(compactBranchFixture, `"condition.value"`, `"missing.value"`, 1)
	calls := 0
	client := assistantFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			assistantToolReply(w, map[string]any{"message": "Ready", "document": json.RawMessage(proposal)})
			return
		}
		assistantToolReply(w, map[string]any{"message": "Repaired", "document": nil, "edits": assistantEdits{Workflows: []assistantWorkflowEdits{{
			RemoveEdges: []workflow.Edge{{Kind: "data", From: workflow.Endpoint{Node: "missing", Port: "value"}, To: workflow.Endpoint{Node: "branch", Port: "condition"}}},
			AddEdges:    []workflow.Edge{{Kind: "data", From: workflow.Endpoint{Node: "condition", Port: "value"}, To: workflow.Endpoint{Node: "branch", Port: "condition"}}},
		}}}})
	})
	client.strictSchema = true
	reply, err := client.Reply(t.Context(), assistantInput(t, "workflow", sampleWorkflow()))
	if err != nil || calls != 2 {
		t.Fatalf("compact repair failed: %v", err)
	}
	var got workflow.Workflow
	_ = json.Unmarshal(reply.Document, &got)
	if got.Name != "Branch and repeat" || len(got.Nodes) != 5 || got.Nodes[1].Position.X != 12 {
		t.Fatal("repair used original source instead of normalized compact proposal")
	}
}

func TestAssistantCompactSchemaHasSharedDefinitionsAndBounds(t *testing.T) {
	for _, kind := range []string{"workflow", "experiment"} {
		schema := assistantDocumentSchema(kind)
		defs := schema["$defs"].(map[string]any)
		properties, enums, stringBytes := 0, 0, 0
		var walk func(any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				if props, ok := x["properties"].(map[string]any); ok {
					properties += len(props)
					for key := range props {
						stringBytes += len(key)
					}
				}
				if values, ok := x["enum"].([]string); ok {
					enums += len(values)
					for _, s := range values {
						stringBytes += len(s)
					}
				}
				if name, ok := x["$ref"].(string); ok {
					if !strings.HasPrefix(name, "#/$defs/") || defs[strings.TrimPrefix(name, "#/$defs/")] == nil {
						t.Fatalf("unresolved ref %s", name)
					}
				}
				for _, child := range x {
					walk(child)
				}
			case []any:
				for _, child := range x {
					walk(child)
				}
			}
		}
		walk(schema)
		if properties > 5000 || enums > 1000 || stringBytes > 120000 {
			t.Fatalf("strict schema limits exceeded: properties=%d enum=%d strings=%d", properties, enums, stringBytes)
		}
		encoded, _ := json.Marshal(schema)
		t.Logf("%s schema: bytes=%d properties=%d enum=%d strings=%d", kind, len(encoded), properties, enums, stringBytes)
	}
}
