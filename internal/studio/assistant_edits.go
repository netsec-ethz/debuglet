// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

type assistantEdits struct {
	Name      *string                  `json:"name"`
	Channels  *[]workflow.Channel      `json:"channels"`
	Workflows []assistantWorkflowEdits `json:"workflows"`
}

type assistantWorkflowEdits struct {
	Participant        string               `json:"participant"`
	Name               *string              `json:"name"`
	Entry              *string              `json:"entry"`
	UpsertNodes        []assistantWireNode  `json:"upsert_nodes"`
	RemoveNodes        []string             `json:"remove_nodes"`
	AddEdges           []workflow.Edge      `json:"add_edges"`
	RemoveEdges        []workflow.Edge      `json:"remove_edges"`
	UpsertCustomBlocks []assistantWireBlock `json:"upsert_custom_blocks"`
}

// Edits operate on a private decoded copy. The caller validates the complete
// result before returning it to the editor; failed edits never change its draft.
func assistantApplyEdits(kind string, raw json.RawMessage, edits assistantEdits) (json.RawMessage, error) {
	operations := len(edits.Workflows)
	if edits.Channels != nil {
		operations += len(*edits.Channels)
	}
	seen := make(map[string]bool)
	for _, edit := range edits.Workflows {
		operations += len(edit.UpsertNodes) + len(edit.RemoveNodes) + len(edit.AddEdges) + len(edit.RemoveEdges) + len(edit.UpsertCustomBlocks)
		if seen[edit.Participant] {
			return nil, errors.New("edit each participant at most once")
		}
		seen[edit.Participant] = true
	}
	if operations > 512 {
		return nil, errors.New("edit contains more than 512 operations")
	}
	if kind == "workflow" {
		if edits.Channels != nil {
			return nil, errors.New("channel edits require an experiment")
		}
		doc, err := DecodeWorkflow(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		if edits.Name != nil {
			doc.Name = *edits.Name
		}
		for _, edit := range edits.Workflows {
			if edit.Participant != "" {
				return nil, errors.New("workflow edits require an empty participant")
			}
			if edits.Name != nil && edit.Name != nil && *edits.Name != *edit.Name {
				return nil, errors.New("conflicting workflow names")
			}
			if err := assistantEditWorkflow(&doc, edit); err != nil {
				return nil, err
			}
		}
		return json.Marshal(doc)
	}
	if kind != "experiment" {
		return nil, errors.New("unsupported document kind")
	}
	doc, err := DecodeExperiment(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if edits.Name != nil {
		doc.Name = *edits.Name
	}
	if edits.Channels != nil {
		doc.Channels = slices.Clone(*edits.Channels)
	}
	for _, edit := range edits.Workflows {
		index := -1
		for i, participant := range doc.Participants {
			if participant.ID == edit.Participant {
				if index >= 0 {
					return nil, errors.New("participant identifier is ambiguous")
				}
				index = i
			}
		}
		if index < 0 || edit.Participant == "" {
			return nil, fmt.Errorf("unknown participant %q", assistantBoundText(edit.Participant, 128))
		}
		if err := assistantEditWorkflow(&doc.Participants[index].Workflow, edit); err != nil {
			return nil, fmt.Errorf("participant %s: %w", assistantBoundText(edit.Participant, 128), err)
		}
	}
	return json.Marshal(doc)
}

func assistantEditWorkflow(doc *workflow.Workflow, edit assistantWorkflowEdits) error {
	if doc.GoCode != nil {
		return errors.New("restore blocks before editing a manual Go program")
	}
	if edit.Name != nil {
		doc.Name = *edit.Name
	}
	if edit.Entry != nil {
		doc.Entry = *edit.Entry
	}
	remove := make(map[string]bool)
	nodes := make(map[string]int)
	for i, node := range doc.Nodes {
		if _, exists := nodes[node.ID]; exists {
			return errors.New("node identifier is ambiguous")
		}
		nodes[node.ID] = i
	}
	for _, id := range edit.RemoveNodes {
		if _, exists := nodes[id]; !exists || id == "" || remove[id] {
			return fmt.Errorf("cannot remove missing or duplicate node %q", assistantBoundText(id, 128))
		}
		remove[id] = true
	}
	upserts := make(map[string]bool)
	for _, wire := range edit.UpsertNodes {
		if wire.ID == "" || upserts[wire.ID] || remove[wire.ID] {
			return errors.New("node upserts require distinct identifiers that are not removed")
		}
		upserts[wire.ID] = true
		node, err := wire.document()
		if err != nil {
			return err
		}
		if i, exists := nodes[node.ID]; exists {
			if node.Position == nil {
				node.Position = doc.Nodes[i].Position
			}
			doc.Nodes[i] = node
		} else {
			doc.Nodes = append(doc.Nodes, node)
		}
	}
	edges := make(map[workflow.Edge]bool)
	for _, edge := range doc.Edges {
		edges[edge] = true
	}
	removedEdges := make(map[workflow.Edge]bool)
	for _, edge := range edit.RemoveEdges {
		if !edges[edge] || removedEdges[edge] {
			return errors.New("cannot remove a missing or duplicate edge")
		}
		removedEdges[edge] = true
	}
	doc.Nodes = slices.DeleteFunc(doc.Nodes, func(node workflow.Node) bool { return remove[node.ID] })
	doc.Edges = slices.DeleteFunc(doc.Edges, func(edge workflow.Edge) bool {
		return removedEdges[edge] || remove[edge.From.Node] || remove[edge.To.Node]
	})
	dissolvedGroups := make(map[string]bool)
	for i := range doc.Groups {
		before := len(doc.Groups[i].NodeIDs)
		doc.Groups[i].NodeIDs = slices.DeleteFunc(doc.Groups[i].NodeIDs, func(id string) bool { return remove[id] })
		dissolvedGroups[doc.Groups[i].ID] = len(doc.Groups[i].NodeIDs) < before && len(doc.Groups[i].NodeIDs) < 2
	}
	doc.Groups = slices.DeleteFunc(doc.Groups, func(group workflow.Group) bool { return dissolvedGroups[group.ID] })
	for _, edge := range edit.AddEdges {
		if edges[edge] || removedEdges[edge] {
			return errors.New("cannot add a duplicate or removed edge")
		}
		edges[edge] = true
		doc.Edges = append(doc.Edges, edge)
	}
	blocks := make(map[string]int)
	for i, block := range doc.CustomBlocks {
		if _, exists := blocks[block.ID]; exists {
			return errors.New("custom block identifier is ambiguous")
		}
		blocks[block.ID] = i
	}
	upserts = make(map[string]bool)
	for _, wire := range edit.UpsertCustomBlocks {
		if wire.ID == "" || upserts[wire.ID] {
			return errors.New("custom block upserts require distinct identifiers")
		}
		upserts[wire.ID] = true
		block, err := wire.document()
		if err != nil {
			return err
		}
		if i, exists := blocks[block.ID]; exists {
			doc.CustomBlocks[i] = block
		} else {
			doc.CustomBlocks = append(doc.CustomBlocks, block)
		}
	}
	return nil
}
