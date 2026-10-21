// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/studio"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func communityTestWorkflow() workflow.Workflow {
	return workflow.Workflow{
		Version: 1, Name: "Shared measurement", Entry: "request",
		Nodes: []workflow.Node{{ID: "request", Block: "http", Inputs: map[string]any{"url": "https://example.test/"}}},
		Edges: []workflow.Edge{},
	}
}

func communityTestJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func communityTestBundle(t *testing.T, wf workflow.Workflow, program workflow.Program) studio.Bundle {
	t.Helper()
	wasm := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	return studio.Bundle{
		Version: 1, Workflow: wf, WorkflowJSON: string(communityTestJSON(t, wf)),
		Source: program.Source, WorkflowSHA256: program.WorkflowSHA256,
		Wasm: wasm, WasmSHA256: communityDocumentDigest(wasm),
		Destinations: program.Destinations, RequireICMP: program.RequireICMP,
	}
}

func TestCommunityDocumentCanonicalSourceAndOptionalBundle(t *testing.T) {
	wf := communityTestWorkflow()
	program, err := workflow.Generate(wf)
	if err != nil {
		t.Fatal(err)
	}
	canonical := communityTestJSON(t, wf)
	indented, err := json.MarshalIndent(wf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	bundle := communityTestJSON(t, communityTestBundle(t, wf, program))
	for _, inputBundle := range []json.RawMessage{nil, []byte("null"), bundle} {
		saved, compiled, err := validateCommunityDocument("workflow", indented, inputBundle)
		if err != nil || !bytes.Equal(saved, canonical) {
			t.Fatalf("saved source: %s, %v", saved, err)
		}
		if bytes.Equal(inputBundle, bundle) {
			if !bytes.Equal(compiled, bundle) {
				t.Fatal("changed the compiled bundle")
			}
		} else if compiled != nil {
			t.Fatal("retained an absent bundle")
		}
	}
}

func TestCommunityDocumentRejectsMalformedOrInvalidSource(t *testing.T) {
	wf := communityTestJSON(t, communityTestWorkflow())
	for name, test := range map[string]struct {
		kind string
		raw  []byte
	}{
		"unknown kind":        {"other", wf},
		"unknown field":       {"workflow", bytes.Replace(wf, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1)},
		"unknown node field":  {"workflow", bytes.Replace(wf, []byte(`"block":"http"`), []byte(`"block":"http","extra":true`), 1)},
		"trailing object":     {"workflow", append(append([]byte{}, wf...), []byte(" {}")...)},
		"null source":         {"workflow", []byte("null")},
		"invalid graph":       {"workflow", bytes.Replace(wf, []byte(`"block":"http"`), []byte(`"block":"missing"`), 1)},
		"oversize workflow":   {"workflow", []byte(strings.Repeat(" ", studio.MaxWorkflowBytes+1))},
		"oversize experiment": {"experiment", []byte(strings.Repeat(" ", studio.MaxExperimentBytes+1))},
	} {
		t.Run(name, func(t *testing.T) {
			assertCommunityDocumentRejected(t, test.kind, test.raw, nil)
		})
	}
}

func TestCommunityWorkflowBundleRejectsMismatchedFields(t *testing.T) {
	for name, change := range map[string]func(*studio.Bundle){
		"version":     func(b *studio.Bundle) { b.Version = 2 },
		"source":      func(b *studio.Bundle) { b.Source += "\n" },
		"source hash": func(b *studio.Bundle) { b.WorkflowSHA256 = strings.Repeat("0", 64) },
		"embedded graph": func(b *studio.Bundle) {
			b.Workflow.Name = "Another workflow"
		},
		"raw graph":    func(b *studio.Bundle) { b.WorkflowJSON += "\n" },
		"destination":  func(b *studio.Bundle) { b.Destinations = []string{"other.test"} },
		"icmp":         func(b *studio.Bundle) { b.RequireICMP = true },
		"wasm hash":    func(b *studio.Bundle) { b.WasmSHA256 = strings.Repeat("0", 64) },
		"wasm magic":   func(b *studio.Bundle) { b.Wasm[0] = 1; b.WasmSHA256 = communityDocumentDigest(b.Wasm) },
		"wasm version": func(b *studio.Bundle) { b.Wasm[4] = 2; b.WasmSHA256 = communityDocumentDigest(b.Wasm) },
		"short wasm":   func(b *studio.Bundle) { b.Wasm = b.Wasm[:4]; b.WasmSHA256 = communityDocumentDigest(b.Wasm) },
	} {
		t.Run(name, func(t *testing.T) {
			wf := communityTestWorkflow()
			program, err := workflow.Generate(wf)
			if err != nil {
				t.Fatal(err)
			}
			bundle := communityTestBundle(t, wf, program)
			change(&bundle)
			assertCommunityDocumentRejected(t, "workflow", communityTestJSON(t, wf), communityTestJSON(t, bundle))
		})
	}
	wf := communityTestWorkflow()
	program, err := workflow.Generate(wf)
	if err != nil {
		t.Fatal(err)
	}
	bundle := communityTestJSON(t, communityTestBundle(t, wf, program))
	for _, malformed := range []json.RawMessage{
		bytes.Replace(bundle, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1),
		append(append([]byte{}, bundle...), []byte(" {}")...),
		[]byte(`[]`),
	} {
		assertCommunityDocumentRejected(t, "workflow", communityTestJSON(t, wf), malformed)
	}
}

func communityTestExperiment(t *testing.T) (workflow.Experiment, studio.ExperimentBundle) {
	t.Helper()
	experiment := workflow.Experiment{
		Version: 1, Kind: "experiment", Name: "Shared experiment",
		Participants: []workflow.Participant{
			{ID: "first", Label: "First", Workflow: communityTestWorkflow()},
			{ID: "second", Label: "Second", Workflow: communityTestWorkflow()},
		},
		Channels: []workflow.Channel{{ID: "reports", From: "first", To: "second", Type: "number"}},
	}
	raw := communityTestJSON(t, experiment)
	bundle := studio.ExperimentBundle{
		Version: 1, Kind: "experiment_bundle", Experiment: experiment,
		ExperimentJSON: string(raw), ExperimentSHA256: communityDocumentDigest(raw),
		RequireTCPListener: true,
	}
	for _, participant := range experiment.Participants {
		wf, program, err := workflow.GenerateParticipant(experiment, participant.ID)
		if err != nil {
			t.Fatal(err)
		}
		compiled := communityTestBundle(t, wf, program)
		bundle.Participants = append(bundle.Participants, studio.ParticipantBundle{ID: participant.ID, Label: participant.Label, Bundle: &compiled})
		bundle.ProgramBytes += len(compiled.Wasm)
		bundle.EncodedProgramBytes += base64.StdEncoding.EncodedLen(len(compiled.Wasm))
	}
	return experiment, bundle
}

func TestCommunityExperimentBundlePreservesGeneratedParticipantContext(t *testing.T) {
	experiment, bundle := communityTestExperiment(t)
	raw, encoded := communityTestJSON(t, experiment), communityTestJSON(t, bundle)
	saved, compiled, err := validateCommunityDocument("experiment", raw, encoded)
	if err != nil || !bytes.Equal(raw, saved) || !bytes.Equal(encoded, compiled) {
		t.Fatalf("valid experiment: %v", err)
	}
	for name, change := range map[string]func(*studio.ExperimentBundle){
		"kind":           func(b *studio.ExperimentBundle) { b.Kind = "other" },
		"source":         func(b *studio.ExperimentBundle) { b.Experiment.Name = "Other experiment" },
		"source hash":    func(b *studio.ExperimentBundle) { b.ExperimentSHA256 = strings.Repeat("0", 64) },
		"raw source":     func(b *studio.ExperimentBundle) { b.ExperimentJSON += "\n" },
		"listener":       func(b *studio.ExperimentBundle) { b.RequireTCPListener = false },
		"program bytes":  func(b *studio.ExperimentBundle) { b.ProgramBytes++ },
		"encoded bytes":  func(b *studio.ExperimentBundle) { b.EncodedProgramBytes++ },
		"missing member": func(b *studio.ExperimentBundle) { b.Participants = b.Participants[:1] },
		"duplicate member": func(b *studio.ExperimentBundle) {
			b.Participants[1] = b.Participants[0]
		},
		"missing bundle": func(b *studio.ExperimentBundle) { b.Participants[0].Bundle = nil },
		"wrong label":    func(b *studio.ExperimentBundle) { b.Participants[0].Label = "Other" },
		"crossed programs": func(b *studio.ExperimentBundle) {
			b.Participants[0].Bundle, b.Participants[1].Bundle = b.Participants[1].Bundle, b.Participants[0].Bundle
		},
		"context fingerprint": func(b *studio.ExperimentBundle) {
			b.Participants[0].Bundle.Workflow.Experiment.Fingerprint = strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			experiment, bundle := communityTestExperiment(t)
			change(&bundle)
			assertCommunityDocumentRejected(t, "experiment", communityTestJSON(t, experiment), communityTestJSON(t, bundle))
		})
	}
}

func TestCommunityBundleSourceMismatchExplainsHowToRebuild(t *testing.T) {
	wf := communityTestWorkflow()
	program, err := workflow.Generate(wf)
	if err != nil {
		t.Fatal(err)
	}
	bundle := communityTestBundle(t, wf, program)
	bundle.Source += "\n"
	experiment, group := communityTestExperiment(t)
	group.Participants[1].Bundle.Source += "\n"
	for _, test := range []struct {
		kind             string
		document, bundle any
	}{
		{"workflow", wf, bundle},
		{"experiment", experiment, group},
	} {
		t.Run(test.kind, func(t *testing.T) {
			document, compiled, err := validateCommunityDocument(test.kind, communityTestJSON(t, test.document), communityTestJSON(t, test.bundle))
			if err == nil || document != nil || compiled != nil {
				t.Fatal("accepted changed generated source")
			}
			status, body, _ := errorEnvelope(err)
			if status != http.StatusBadRequest || body.Code != CodeInvalidRequest ||
				!strings.Contains(body.Message, "rebuild it with the current Studio and SDK") {
				t.Fatalf("missing actionable rebuild error: %d %+v", status, body)
			}
		})
	}
}

func assertCommunityDocumentRejected(t *testing.T, kind string, document, bundle json.RawMessage) {
	t.Helper()
	saved, compiled, err := validateCommunityDocument(kind, document, bundle)
	if err == nil || saved != nil || compiled != nil {
		t.Fatal("accepted invalid saved source or compiled bundle")
	}
	status, body, _ := errorEnvelope(err)
	if status != http.StatusBadRequest || body.Code != CodeInvalidRequest {
		t.Fatalf("error envelope = %d %s", status, body.Code)
	}
}
