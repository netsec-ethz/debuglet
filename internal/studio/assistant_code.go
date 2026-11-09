// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

// Function replacements are deliberately separate from visual graph proposals:
// accepting Go must not silently rewrite the blocks the user may restore later.
type assistantCodeEdit struct {
	Participant string `json:"participant"`
	GoCode      string `json:"go_code"`
}

type assistantCodeContext struct {
	Participant string `json:"participant"`
	Source      string `json:"source"`
}

func assistantCodeSchema() map[string]any {
	return assistantSchemaObject(map[string]any{
		"message": map[string]any{"type": "string"},
		"code": map[string]any{"type": []string{"array", "null"}, "items": assistantSchemaObject(map[string]any{
			"participant": map[string]any{"type": "string", "description": "Existing participant ID, or empty for a single workflow."},
			"go_code":     map[string]any{"type": "string", "description": "Complete replacement function declarations. Keep the generated entry function; no package, imports, globals, main or init."},
		})},
	})
}

func assistantPrepareCode(kind string, raw json.RawMessage) (json.RawMessage, []assistantCodeContext, error) {
	// A blank canvas has no callable entry. Seed only that empty case; meaningful
	// saved graphs are never replaced or repaired implicitly in code mode.
	seed := func(w *workflow.Workflow) {
		if len(w.Nodes) == 0 && len(w.Edges) == 0 && len(w.Groups) == 0 && w.GoCode == nil {
			if w.Name == "" {
				w.Name = "Go program"
			}
			w.Entry = "code_entry"
			w.Nodes = []workflow.Node{{ID: "code_entry", Block: "wait", Inputs: map[string]any{"duration_ms": float64(0)}}}
			w.Edges = []workflow.Edge{}
		}
	}
	var contexts []assistantCodeContext
	if kind == "workflow" {
		w, err := DecodeWorkflow(bytes.NewReader(raw))
		if err != nil {
			return nil, nil, err
		}
		seed(&w)
		p, err := workflow.Generate(w)
		if err != nil {
			return nil, nil, err
		}
		contexts = append(contexts, assistantCodeContext{Source: p.Source})
		raw, err = json.Marshal(w)
		if err != nil {
			return nil, nil, err
		}
	} else if kind == "experiment" {
		e, err := DecodeExperiment(bytes.NewReader(raw))
		if err != nil {
			return nil, nil, err
		}
		for i := range e.Participants {
			seed(&e.Participants[i].Workflow)
		}
		for _, participant := range e.Participants {
			_, p, err := workflow.GenerateParticipant(e, participant.ID)
			if err != nil {
				return nil, nil, err
			}
			contexts = append(contexts, assistantCodeContext{Participant: participant.ID, Source: p.Source})
		}
		raw, err = json.Marshal(e)
		if err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, errors.New("unsupported document kind")
	}
	size := 0
	for _, item := range contexts {
		size += len(item.Source)
	}
	if size > 512<<10 {
		return nil, nil, errors.New("generated source is too large for the assistant")
	}
	return raw, contexts, nil
}

func assistantApplyCode(kind string, raw json.RawMessage, edits []assistantCodeEdit) (json.RawMessage, error) {
	if len(edits) == 0 || len(edits) > 16 {
		return nil, errors.New("code needs one to sixteen existing program replacements")
	}
	seen := map[string]bool{}
	for _, edit := range edits {
		if seen[edit.Participant] || len(edit.GoCode) == 0 || len(edit.GoCode) > 256<<10 {
			return nil, errors.New("each program needs one nonempty function replacement of at most 256 KiB")
		}
		seen[edit.Participant] = true
	}
	if kind == "workflow" {
		if len(edits) != 1 || edits[0].Participant != "" {
			return nil, errors.New("a workflow code replacement needs an empty participant")
		}
		w, err := DecodeWorkflow(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		w.GoCode = &edits[0].GoCode
		return json.Marshal(w)
	}
	e, err := DecodeExperiment(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	for _, edit := range edits {
		found := false
		for i := range e.Participants {
			if e.Participants[i].ID == edit.Participant {
				e.Participants[i].Workflow.GoCode = &edit.GoCode
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown participant %s", assistantBoundText(edit.Participant, 128))
		}
	}
	return json.Marshal(e)
}

func assistantHasGoCode(kind string, raw json.RawMessage) bool {
	var doc struct {
		GoCode       *string `json:"go_code"`
		Participants []struct {
			Workflow struct {
				GoCode *string `json:"go_code"`
			} `json:"workflow"`
		} `json:"participants"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	if kind == "workflow" {
		return doc.GoCode != nil
	}
	for _, participant := range doc.Participants {
		if participant.Workflow.GoCode != nil {
			return true
		}
	}
	return false
}

func assistantValidatePresentation(kind string, raw json.RawMessage) error {
	var diagnostics []workflow.ExperimentDiagnostic
	if kind == "workflow" {
		w, err := DecodeWorkflow(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		for _, d := range workflow.ValidatePresentation(w, 10) {
			diagnostics = append(diagnostics, workflow.ExperimentDiagnostic{Diagnostic: d})
		}
	} else {
		e, err := DecodeExperiment(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		for _, p := range e.Participants {
			for _, d := range workflow.ValidatePresentation(p.Workflow, 10) {
				diagnostics = append(diagnostics, workflow.ExperimentDiagnostic{Participant: p.ID, Diagnostic: d})
			}
		}
	}
	if len(diagnostics) != 0 {
		return assistantValidationError(diagnostics)
	}
	return nil
}

const assistantCodeInstructions = `The user explicitly chose Go authoring. Return propose_document with a brief message and code function replacements, or code:null and a necessary clarification. The code_context contains the actual generated program for every current participant. Replace all editable function declarations for each changed participant; keep its generated runN() error entry. The server preserves the current blocks, participants and channels exactly. Never claim the saved diagram reflects edited Go, or that compilation proves runtime success. Do not return a document, edits, package, imports, globals, main, init or compiler directives. Do not change participant/channel topology; explain if the user must adjust that visual setup first.
Only fmt, json, os, guest, debuglet, time, strings and math are available. Managed startup joins the experiment before calling runN and owns runtime and experiment globals. Only experiment programs have experiment. Use existing generated functions when helpful; helper functions are allowed. Keep loops, memory, network operations and output bounded, preserve errors and unavailable values, and close sockets. Code cannot bypass executor policy, admission or unsupported host capabilities.
The SDK supports debuglet.DialTimeout(network,address string,timeout time.Duration)(*debuglet.Socket,error) for tcp,tls,udp,ip4:icmp; Socket has Read([]byte)(int,error), Write([]byte)(int,error), Close()error, SetReadDeadline(time.Time)error and SetWriteDeadline(time.Time)error. Read/write calls may block guest scheduling. A TCP Write controls application bytes, not on-wire segmentation. Software sleeps cannot guarantee exact packet timing: record achieved timing. Basic arbitrary payload bytes can be created with make([]byte,n), indexing, append, copy and byte shifts; no encoding/binary import.
Existing generated source shows guest operation calling conventions. runtime.Record(node,block string,outputs map[string]any)error publishes bounded output, runtime.Fail(node,block string,err error)error records an error, runtime.Step()error counts bounded actions. Preserve calls for visible results. For a simple report, return runtime.Record("result","emit",map[string]any{"name":"result","value":value}). More structured reports use guest.Report(block string,inputs map[string]any)(map[string]any,error), followed by runtime.Record with the returned outputs; copy the original report inputs when present. Never fabricate an SDK method, destination, listener or successful result. Custom functions are compiled before the user receives the proposal.`
