// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"strings"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

// The compact encoding is only an authoring transport. The editor and execution
// continue to use Workflow, with separate data and control edges.
func assistantCompactSchema(position, custom map[string]any) (map[string]any, map[string]any) {
	str := func() map[string]any { return map[string]any{"type": "string"} }
	ref := func(name string) map[string]any { return map[string]any{"$ref": "#/$defs/" + name} }
	array := func(item any) map[string]any { return map[string]any{"type": "array", "items": item} }
	defs := map[string]any{
		"position":         position,
		"output_reference": assistantSchemaObject(map[string]any{"from": map[string]any{"type": "string", "description": "Existing node ID and output port, separated by one dot: node.port."}}),
		"json_literal":     assistantSchemaObject(map[string]any{"json": map[string]any{"type": "string", "description": "A JSON-encoded literal value. Objects here are data, never output references."}}),
	}
	for _, kind := range []string{"string", "number", "boolean", "strings", "numbers", "object", "any"} {
		choices := []any{ref("output_reference")}
		switch kind {
		case "object":
			choices = append(choices, ref("json_literal"))
		case "any":
			choices = append(choices, str(), map[string]any{"type": "number"}, map[string]any{"type": "boolean"}, ref("json_literal"))
		case "strings", "numbers":
			choices = append(choices, array(map[string]any{"type": kind[:len(kind)-1]}))
		default:
			choices = append(choices, map[string]any{"type": kind})
		}
		defs["binding_"+kind] = map[string]any{"anyOf": choices}
		defs["optional_"+kind] = map[string]any{"anyOf": []any{ref("binding_" + kind), map[string]any{"type": "null"}}, "description": "Null omits this input and uses the catalog default."}
	}
	variants := []any{}
	for _, block := range workflow.Catalog() {
		inputs := map[string]any{}
		for _, port := range block.Inputs {
			binding := ref("binding_" + port.Type)
			if !port.Required {
				binding = ref("optional_" + port.Type)
			}
			inputs[port.Name] = binding
		}
		control := map[string]any{}
		for _, port := range block.ControlOutputs {
			control[port] = map[string]any{"type": []string{"string", "null"}, "description": "Next action node ID, or null to end this branch."}
		}
		controlName := "control_" + strings.Join(block.ControlOutputs, "_")
		defs[controlName] = assistantSchemaObject(control)
		variants = append(variants, assistantSchemaObject(map[string]any{
			"id": str(), "block": map[string]any{"type": "string", "enum": []string{block.ID}},
			"inputs": assistantSchemaObject(inputs), "control": ref(controlName), "position": ref("position"),
		}))
	}
	variants = append(variants, assistantSchemaObject(map[string]any{
		"id": str(), "custom_block": str(), "position": ref("position"),
		"inputs":  array(assistantSchemaObject(map[string]any{"port": str(), "value": ref("binding_any")})),
		"control": ref("control_next"),
	}))
	defs["compact_node"] = map[string]any{"anyOf": variants}
	graph := assistantSchemaObject(map[string]any{
		"format":  map[string]any{"type": "string", "enum": []string{"compact"}},
		"version": map[string]any{"type": "integer", "enum": []int{1}}, "name": str(), "entry": str(),
		"nodes": array(ref("compact_node")), "custom_blocks": array(custom),
		"groups": array(assistantSchemaObject(map[string]any{"id": str(), "label": str(), "node_ids": array(str()), "position": position})),
	})
	// The root workflow may be nullable; participant workflows must never be.
	definition := map[string]any{}
	for key, value := range graph {
		definition[key] = value
	}
	defs["compact_workflow"] = definition
	return graph, defs
}
