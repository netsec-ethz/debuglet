// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"encoding/json"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func TestDocumentRejectsWeakenedSCIONRequirements(t *testing.T) {
	wf := workflow.Workflow{Version: 1, Name: "SCION listener", Entry: "listen", Nodes: []workflow.Node{{ID: "listen", Block: "scion_listener_address"}}}
	p, err := workflow.Generate(wf)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := json.Marshal(wf)
	wasm := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	bundle := Bundle{Version: 1, Workflow: wf, WorkflowJSON: string(source), Source: p.Source, WorkflowSHA256: p.WorkflowSHA256, Wasm: wasm, WasmSHA256: DocumentDigest(wasm), Destinations: p.Destinations, RequireSCION: p.RequireSCION, RequireSCIONListener: p.RequireSCIONListener, RequiredHostFunctions: p.RequiredHostFunctions}
	raw, _ := json.Marshal(bundle)
	if _, _, err := ValidateDocument("workflow", source, raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"protocol", "listener", "host functions"} {
		modified := bundle
		switch field {
		case "protocol":
			modified.RequireSCION = false
		case "listener":
			modified.RequireSCIONListener = false
		case "host functions":
			modified.RequiredHostFunctions = nil
		}
		raw, _ := json.Marshal(modified)
		if _, _, err := ValidateDocument("workflow", source, raw); err == nil {
			t.Fatalf("accepted weakened %s", field)
		}
	}
}
