// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"encoding/json"
	"reflect"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

// The editor permits unfinished, disconnected actions. An assistant proposal
// must connect its new/changed actions without requiring unrelated draft nodes
// to be finished. Compare both attempts against the original user draft.
func assistantValidateReachability(kind string, original, proposed json.RawMessage) error {
	decode := func(raw json.RawMessage) ([]workflow.Participant, error) {
		if kind == "workflow" {
			var w workflow.Workflow
			err := json.Unmarshal(raw, &w)
			return []workflow.Participant{{Workflow: w}}, err
		}
		var e workflow.Experiment
		err := json.Unmarshal(raw, &e)
		return e.Participants, err
	}
	before, err := decode(original)
	if err != nil {
		return err
	}
	after, err := decode(proposed)
	if err != nil {
		return err
	}
	originals := make(map[string]workflow.Workflow, len(before))
	for _, p := range before {
		originals[p.ID] = p.Workflow
	}
	pure := map[string]bool{}
	for _, block := range workflow.Catalog() {
		pure[block.ID] = block.Pure
	}
	var diagnostics []workflow.ExperimentDiagnostic
	for _, p := range after {
		oldActions, oldReachable := assistantActionReachability(originals[p.ID], pure)
		actions, reachable := assistantActionReachability(p.Workflow, pure)
		for _, node := range p.Workflow.Nodes {
			if pure[node.Block] || reachable[node.ID] {
				continue
			}
			old, exists := oldActions[node.ID]
			if exists && !oldReachable[node.ID] && reflect.DeepEqual(old, actions[node.ID]) {
				continue
			}
			diagnostics = append(diagnostics, workflow.ExperimentDiagnostic{Participant: p.ID, Diagnostic: workflow.Diagnostic{
				Node: node.ID, Message: "Action is disconnected from the entry; connect it to the intended control path. Data wires alone do not execute actions. Preserve requested measurements.",
			}})
		}
	}
	if len(diagnostics) != 0 {
		return assistantValidationError(diagnostics)
	}
	return nil
}

type assistantActionSource struct {
	Block      string
	Inputs     map[string]any
	Data       map[workflow.Edge]bool
	Definition *workflow.CustomBlock
}

func assistantActionReachability(w workflow.Workflow, pure map[string]bool) (map[string]*assistantActionSource, map[string]bool) {
	custom := make(map[string]*workflow.CustomBlock, len(w.CustomBlocks))
	for _, block := range w.CustomBlocks {
		block.Label, block.Description = "", ""
		custom[block.ID] = &block
	}
	actions := map[string]*assistantActionSource{}
	for _, node := range w.Nodes {
		if !pure[node.Block] {
			if len(node.Inputs) == 0 {
				node.Inputs = nil
			}
			actions[node.ID] = &assistantActionSource{node.Block, node.Inputs, map[workflow.Edge]bool{}, custom[node.Block]}
		}
	}
	next := map[string][]string{}
	for _, edge := range w.Edges {
		if edge.Kind == "control" {
			next[edge.From.Node] = append(next[edge.From.Node], edge.To.Node)
		} else if action := actions[edge.To.Node]; action != nil {
			action.Data[edge] = true
		}
	}
	reachable := map[string]bool{}
	pending := []string{w.Entry}
	for len(pending) != 0 {
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if reachable[id] {
			continue
		}
		reachable[id] = true
		pending = append(pending, next[id]...)
	}
	return actions, reachable
}
