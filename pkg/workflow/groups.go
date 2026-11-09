// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"fmt"
	"math"
	"strings"
)

type groupTree struct {
	members []map[string]bool
	parent  []int // -1 denotes the workflow overview.
}

func workflowGroupTree(w Workflow) (groupTree, []Diagnostic) {
	var ds []Diagnostic
	add := func(message string) { ds = append(ds, Diagnostic{Message: message}) }
	if len(w.Groups) > 64 {
		return groupTree{}, []Diagnostic{{Message: "workflow has more than 64 groups"}}
	}
	tree := groupTree{members: make([]map[string]bool, len(w.Groups)), parent: make([]int, len(w.Groups))}
	nodes, ids := map[string]bool{}, map[string]bool{}
	for _, node := range w.Nodes {
		nodes[node.ID] = true
	}
	for i, g := range w.Groups {
		tree.members[i], tree.parent[i] = map[string]bool{}, -1
		if !identifier.MatchString(g.ID) || ids[g.ID] || nodes[g.ID] {
			add("group id must be valid and distinct from node and group ids")
		}
		ids[g.ID] = true
		if strings.TrimSpace(g.Label) == "" || len(g.Label) > 128 {
			add("group needs a label of at most 128 bytes")
		}
		if len(g.NodeIDs) < 2 || len(g.NodeIDs) > 128 {
			add("group must contain 2–128 nodes")
		}
		for _, id := range g.NodeIDs {
			if !nodes[id] || tree.members[i][id] {
				add("group members must be distinct existing nodes")
			}
			tree.members[i][id] = true
		}
		if g.Position != nil && (math.IsNaN(g.Position.X) || math.IsInf(g.Position.X, 0) || math.IsNaN(g.Position.Y) || math.IsInf(g.Position.Y, 0)) {
			add("group position must be finite")
		}
	}
	if len(ds) != 0 {
		return tree, ds
	}
	for i, a := range tree.members {
		for j, b := range tree.members {
			if i == j {
				continue
			}
			overlap := 0
			for id := range a {
				if b[id] {
					overlap++
				}
			}
			if i < j && overlap > 0 && !(overlap == len(a) && len(a) < len(b)) && !(overlap == len(b) && len(b) < len(a)) {
				add(fmt.Sprintf("groups %s and %s must be disjoint or one must strictly contain the other", w.Groups[i].ID, w.Groups[j].ID))
			}
			if overlap == len(a) && len(a) < len(b) && (tree.parent[i] < 0 || len(b) < len(tree.members[tree.parent[i]])) {
				tree.parent[i] = j
			}
		}
	}
	return tree, ds
}

// ValidatePresentation limits visible cards at the overview and inside each
// group. It checks group metadata, not executable graph semantics. Call Validate
// separately. This authoring check deliberately does not restrict manual drafts.
func ValidatePresentation(w Workflow, maxVisible int) []Diagnostic {
	if maxVisible < 1 {
		return []Diagnostic{{Message: "visible block limit must be positive"}}
	}
	tree, ds := workflowGroupTree(w)
	if len(ds) != 0 {
		return ds
	}
	counts := make([]int, len(w.Groups)+1) // Index 0 is the overview.
	for _, parent := range tree.parent {
		counts[parent+1]++
	}
	for _, node := range w.Nodes {
		parent := -1
		for i, members := range tree.members {
			if members[node.ID] && (parent < 0 || len(members) < len(tree.members[parent])) {
				parent = i
			}
		}
		counts[parent+1]++
	}
	for i, count := range counts {
		if count <= maxVisible {
			continue
		}
		view := "workflow overview"
		if i > 0 {
			view = "group " + w.Groups[i-1].ID
		}
		ds = append(ds, Diagnostic{Message: fmt.Sprintf("%s shows %d blocks; organize it into meaningful groups with at most %d visible blocks per level", view, count, maxVisible)})
	}
	return ds
}
