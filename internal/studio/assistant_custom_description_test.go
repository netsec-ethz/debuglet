// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAssistantCustomDescriptionSchemaAndEdits(t *testing.T) {
	schema := assistantDocumentSchema("workflow")
	graph := schema["properties"].(map[string]any)["document"].(map[string]any)
	custom := graph["properties"].(map[string]any)["custom_blocks"].(map[string]any)["items"].(map[string]any)
	if custom["properties"].(map[string]any)["description"].(map[string]any)["type"] != "string" {
		t.Fatal("provider cannot describe custom blocks")
	}
	wf := sampleWorkflow()
	raw, _ := json.Marshal(wf)
	for _, description := range []string{"", "Keep valid values and retain unavailable results.", strings.Repeat("x", 1025)} {
		block := assistantWireBlock{ID: "helper", Label: "Helper", Description: description, Code: "return nil, nil"}
		updated, err := assistantApplyEdits("workflow", raw, assistantEdits{Workflows: []assistantWorkflowEdits{{UpsertCustomBlocks: []assistantWireBlock{block}}}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = assistantValidateDocument("workflow", updated)
		if (err == nil) != (len(description) <= 1024) {
			t.Fatalf("description with %d bytes: %v", len(description), err)
		}
		doc, err := DecodeWorkflow(bytes.NewReader(updated))
		if err != nil || doc.CustomBlocks[0].Description != description {
			t.Fatalf("edit lost custom description: %v", err)
		}
	}
	var legacy assistantWireBlock
	if err := assistantDecode([]byte(`{"id":"helper","label":"Helper","inputs":[],"outputs":[],"code":"return nil,nil"}`), &legacy); err != nil || legacy.Description != "" {
		t.Fatalf("legacy custom block was rejected: %v", err)
	}
}
