// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func (w assistantWireWorkflow) compactDocument() (workflow.Workflow, error) {
	doc := workflow.Workflow{Version: w.Version, Name: w.Name, Entry: w.Entry, Nodes: []workflow.Node{}, Edges: []workflow.Edge{}, Groups: w.Groups}
	if w.Edges != nil {
		return doc, fmt.Errorf("compact workflows use input bindings and control successors, not edges")
	}
	catalog := map[string]workflow.Block{}
	for _, block := range workflow.Catalog() {
		catalog[block.ID] = block
	}
	custom := map[string]bool{}
	for _, wire := range w.CustomBlocks {
		block, err := wire.document()
		if err != nil {
			return doc, err
		}
		if _, exists := catalog[block.ID]; exists {
			return doc, fmt.Errorf("duplicate or reserved custom block %s", assistantBoundText(block.ID, 128))
		}
		custom[block.ID] = true
		catalog[block.ID] = workflow.Block{ID: block.ID, Inputs: block.Inputs, ControlOutputs: []string{"next"}}
		doc.CustomBlocks = append(doc.CustomBlocks, block)
	}
	for _, wire := range w.Nodes {
		node := workflow.Node{ID: wire.ID, Block: wire.Block, Position: wire.Position, Inputs: map[string]any{}}
		if wire.InputsJSON != "" || (wire.Block == "") == (wire.CustomBlock == "") {
			return doc, fmt.Errorf("node %s: choose one block and compact inputs only", assistantBoundText(wire.ID, 128))
		}
		if wire.CustomBlock != "" {
			node.Block = wire.CustomBlock
		}
		block, known := catalog[node.Block]
		if !known || custom[node.Block] != (wire.CustomBlock != "") {
			return doc, fmt.Errorf("node %s: unknown built-in or custom block reference", assistantBoundText(wire.ID, 128))
		}
		bindings, err := wire.compactInputs()
		if err != nil {
			return doc, fmt.Errorf("node %s: %w", assistantBoundText(wire.ID, 128), err)
		}
		for _, port := range block.Inputs {
			raw, present := bindings[port.Name]
			delete(bindings, port.Name)
			if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				if port.Required {
					return doc, fmt.Errorf("node %s: required input %s needs a literal or output reference", assistantBoundText(wire.ID, 128), port.Name)
				}
				continue
			}
			value, from, err := assistantCompactBinding(raw)
			if err != nil {
				return doc, fmt.Errorf("node %s input %s: %w", assistantBoundText(wire.ID, 128), port.Name, err)
			}
			if from != nil {
				doc.Edges = append(doc.Edges, workflow.Edge{Kind: "data", From: *from, To: workflow.Endpoint{Node: wire.ID, Port: port.Name}})
			} else {
				node.Inputs[port.Name] = value
			}
		}
		if len(bindings) != 0 {
			return doc, fmt.Errorf("node %s: unknown input port", assistantBoundText(wire.ID, 128))
		}
		if wire.Control == nil || len(wire.Control) != len(block.ControlOutputs) {
			return doc, fmt.Errorf("node %s: control must name exactly this block's control outputs", assistantBoundText(wire.ID, 128))
		}
		for _, port := range block.ControlOutputs {
			target, exists := wire.Control[port]
			if !exists || (target != nil && *target == "") {
				return doc, fmt.Errorf("node %s: control %s needs an action ID or null", assistantBoundText(wire.ID, 128), port)
			}
			if target != nil {
				doc.Edges = append(doc.Edges, workflow.Edge{Kind: "control", From: workflow.Endpoint{Node: wire.ID, Port: port}, To: workflow.Endpoint{Node: *target, Port: "in"}})
			}
		}
		doc.Nodes = append(doc.Nodes, node)
	}
	return doc, nil
}

func (n assistantWireNode) compactInputs() (map[string]json.RawMessage, error) {
	bindings := map[string]json.RawMessage{}
	if n.CustomBlock == "" {
		if err := assistantDecode(n.Inputs, &bindings); err != nil || bindings == nil {
			return nil, fmt.Errorf("inputs must be an object of literal or output bindings")
		}
		return bindings, nil
	}
	var entries []struct {
		Port  string          `json:"port"`
		Value json.RawMessage `json:"value"`
	}
	if err := assistantDecode(n.Inputs, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("custom inputs must be an array of port/value bindings")
	}
	for _, entry := range entries {
		if _, exists := bindings[entry.Port]; exists || entry.Port == "" || len(entry.Value) == 0 {
			return nil, fmt.Errorf("custom inputs need unique named ports and values")
		}
		bindings[entry.Port] = entry.Value
	}
	return bindings, nil
}

func assistantCompactBinding(raw json.RawMessage) (any, *workflow.Endpoint, error) {
	var value any
	if err := assistantDecode(raw, &value); err != nil {
		return nil, nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return value, nil, nil
	}
	if len(object) == 1 {
		if from, ok := object["from"].(string); ok {
			node, port, found := strings.Cut(from, ".")
			if found && node != "" && port != "" && !strings.Contains(port, ".") {
				return nil, &workflow.Endpoint{Node: node, Port: port}, nil
			}
		}
		if literal, ok := object["json"].(string); ok {
			if err := assistantDecode([]byte(literal), &value); err == nil {
				return value, nil, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("binding object must be {from:node.port} or {json:encoded literal}")
}
