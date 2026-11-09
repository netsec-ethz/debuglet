// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCustomDescriptionPreservesLegacySourceAndHash(t *testing.T) {
	const legacy = `{"version":1,"name":"Legacy helper","entry":"helper","nodes":[{"id":"helper","block":"custom"}],"edges":[],"custom_blocks":[{"id":"custom","label":"Custom","inputs":[],"outputs":[],"code":"return map[string]any{}, nil"}]}`
	var w Workflow
	if err := json.Unmarshal([]byte(legacy), &w); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(w)
	if err != nil || string(encoded) != legacy {
		t.Fatalf("legacy source changed: %s, %v", encoded, err)
	}
	program, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(legacy))
	if program.WorkflowSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("legacy workflow fingerprint changed")
	}
	w.CustomBlocks[0].Description = "Return an empty result."
	described, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if described.WorkflowSHA256 == program.WorkflowSHA256 || strings.ReplaceAll(described.Source, described.WorkflowSHA256, program.WorkflowSHA256) != program.Source {
		t.Fatal("description must affect source identity without changing execution")
	}
	if catalogFor(w)["custom"].Description != w.CustomBlocks[0].Description {
		t.Fatal("custom description was not exposed with the block")
	}
}

func TestCustomDescriptionByteLimit(t *testing.T) {
	w := sampleWorkflow()
	w.CustomBlocks = []CustomBlock{{ID: "helper", Label: "Helper", Code: "return nil, nil"}}
	for _, description := range []string{"", strings.Repeat("x", 1024), strings.Repeat("é", 512), strings.Repeat("x", 1025), strings.Repeat("é", 513)} {
		w.CustomBlocks[0].Description = description
		ds := Validate(w)
		if (len(ds) == 0) != (len(description) <= 1024) {
			t.Fatalf("description with %d bytes: %v", len(description), ds)
		}
	}
}
