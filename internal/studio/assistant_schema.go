// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

// OpenAI strict schemas forbid open-ended object properties. Keep the graph
// scaffold typed, and encode only the literal input maps and custom port defaults as
// JSON strings. These are decoded and validated before returning normal editor
// JSON. Other compatible providers continue using the existing document format.
func assistantDocumentSchema(kind string) map[string]any {
	str := func() map[string]any { return map[string]any{"type": "string"} }
	array := func(items any) map[string]any { return map[string]any{"type": "array", "items": items} }
	endpoint := assistantSchemaObject(map[string]any{"node": str(), "port": str()})
	position := assistantSchemaObject(map[string]any{"x": map[string]any{"type": "number"}, "y": map[string]any{"type": "number"}})
	position["type"] = []string{"object", "null"}
	port := assistantSchemaObject(map[string]any{"name": str(), "type": map[string]any{"type": "string", "enum": []string{"string", "number", "boolean", "numbers", "strings", "object", "any"}}, "required": map[string]any{"type": "boolean"}, "default_json": map[string]any{"type": "string", "description": "JSON-encoded default literal, or null encoded as a string when absent."}})
	graph := assistantSchemaObject(map[string]any{
		"version": map[string]any{"type": "integer", "enum": []int{1}}, "name": str(), "entry": str(),
		"nodes": array(assistantSchemaObject(map[string]any{
			"id": str(), "block": str(), "inputs_json": map[string]any{"type": "string", "description": "A JSON object containing literal input values only; use {} when all inputs are wired."}, "position": position,
		})),
		"edges": array(assistantSchemaObject(map[string]any{
			"kind": map[string]any{"type": "string", "enum": []string{"control", "data"}}, "from": endpoint, "to": endpoint,
		})),
		"custom_blocks": array(assistantSchemaObject(map[string]any{"id": str(), "label": str(), "inputs": array(port), "outputs": array(port), "code": str()})),
		"groups":        array(assistantSchemaObject(map[string]any{"id": str(), "label": str(), "node_ids": array(str()), "position": position})),
	})
	document := graph
	if kind == "experiment" {
		document = assistantSchemaObject(map[string]any{
			"version": map[string]any{"type": "integer", "enum": []int{1}},
			"kind":    map[string]any{"type": "string", "enum": []string{"experiment"}}, "name": str(),
			"participants": array(assistantSchemaObject(map[string]any{"id": str(), "label": str(), "workflow": graph})),
			"channels": array(assistantSchemaObject(map[string]any{
				"id": str(), "from": str(), "to": str(), "type": str(), "response_type": str(),
			})),
		})
	}
	document["type"] = []string{"object", "null"}
	return assistantSchemaObject(map[string]any{
		"message": str(), "document": document,
		"action": map[string]any{"type": "string", "enum": []string{"", "coordinate"}, "description": "Use coordinate only to offer workflow conversion; otherwise use an empty string. Use null document for a clarification or conversion offer."},
	})
}

func assistantSchemaObject(properties map[string]any) map[string]any {
	required := make([]string, 0, len(properties))
	for name := range properties {
		required = append(required, name)
	}
	sort.Strings(required)
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}

type assistantWireWorkflow struct {
	Version      int                  `json:"version"`
	Name         string               `json:"name"`
	Entry        string               `json:"entry"`
	Nodes        []assistantWireNode  `json:"nodes"`
	Edges        []workflow.Edge      `json:"edges"`
	CustomBlocks []assistantWireBlock `json:"custom_blocks"`
	Groups       []workflow.Group     `json:"groups"`
}

type assistantWireNode struct {
	ID         string             `json:"id"`
	Block      string             `json:"block"`
	InputsJSON string             `json:"inputs_json"`
	Position   *workflow.Position `json:"position"`
}

type assistantWireBlock struct {
	ID      string              `json:"id"`
	Label   string              `json:"label"`
	Inputs  []assistantWirePort `json:"inputs"`
	Outputs []assistantWirePort `json:"outputs"`
	Code    string              `json:"code"`
}

type assistantWirePort struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	DefaultJSON string `json:"default_json"`
}

func assistantDecodePorts(wire []assistantWirePort) ([]workflow.Port, error) {
	ports := make([]workflow.Port, len(wire))
	for i, p := range wire {
		ports[i] = workflow.Port{Name: p.Name, Type: p.Type, Required: p.Required}
		if err := assistantDecode([]byte(p.DefaultJSON), &ports[i].Default); err != nil {
			return nil, fmt.Errorf("port %s: default_json must encode a JSON value", assistantBoundText(p.Name, 128))
		}
	}
	return ports, nil
}

func (w assistantWireWorkflow) document() (workflow.Workflow, error) {
	doc := workflow.Workflow{Version: w.Version, Name: w.Name, Entry: w.Entry, Edges: w.Edges, Nodes: []workflow.Node{}, Groups: w.Groups}
	for _, n := range w.Nodes {
		node := workflow.Node{ID: n.ID, Block: n.Block, Position: n.Position}
		if err := assistantDecode([]byte(n.InputsJSON), &node.Inputs); err != nil || node.Inputs == nil {
			return doc, fmt.Errorf("node %s: inputs_json must encode a JSON object of literal input values", assistantBoundText(n.ID, 128))
		}
		doc.Nodes = append(doc.Nodes, node)
	}
	for _, block := range w.CustomBlocks {
		inputs, err := assistantDecodePorts(block.Inputs)
		if err != nil {
			return doc, err
		}
		outputs, err := assistantDecodePorts(block.Outputs)
		if err != nil {
			return doc, err
		}
		doc.CustomBlocks = append(doc.CustomBlocks, workflow.CustomBlock{ID: block.ID, Label: block.Label, Inputs: inputs, Outputs: outputs, Code: block.Code})
	}
	return doc, nil
}

func assistantDecodeWireDocument(kind string, raw json.RawMessage) (json.RawMessage, error) {
	if kind == "workflow" {
		var wire assistantWireWorkflow
		if err := assistantDecode(raw, &wire); err != nil {
			return nil, err
		}
		doc, err := wire.document()
		if err != nil {
			return nil, err
		}
		return json.Marshal(doc)
	}
	var wire struct {
		Version      int    `json:"version"`
		Kind         string `json:"kind"`
		Name         string `json:"name"`
		Participants []struct {
			ID       string                `json:"id"`
			Label    string                `json:"label"`
			Workflow assistantWireWorkflow `json:"workflow"`
		} `json:"participants"`
		Channels []workflow.Channel `json:"channels"`
	}
	if err := assistantDecode(raw, &wire); err != nil {
		return nil, err
	}
	doc := workflow.Experiment{Version: wire.Version, Kind: wire.Kind, Name: wire.Name, Channels: wire.Channels}
	for _, p := range wire.Participants {
		wf, err := p.Workflow.document()
		if err != nil {
			return nil, fmt.Errorf("participant %s: %w", assistantBoundText(p.ID, 128), err)
		}
		doc.Participants = append(doc.Participants, workflow.Participant{ID: p.ID, Label: p.Label, Workflow: wf})
	}
	return json.Marshal(doc)
}

const assistantStrictInstructions = `
The propose_document schema uses a transport encoding: replace each node's inputs object with inputs_json, a JSON-encoded object string. Custom port defaults use default_json, a JSON-encoded value string ("null" when absent). Use empty arrays for absent custom_blocks and groups; do not copy catalog-only fields such as category or pure into custom definitions. Everything else keeps the described graph semantics. Use null position for new nodes (the editor lays them out); preserve existing positions. Use an empty action string for ordinary edits. Use null document only for clarification or a coordinate offer. Return only the tool call, with a brief explanation of any defaults. The server decodes these JSON strings and validates the full graph; a schema-valid response can still have invalid graph semantics.`
