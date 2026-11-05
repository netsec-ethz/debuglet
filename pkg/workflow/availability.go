// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"fmt"
	"maps"
)

// ValidateOutputAvailability is an optional proposal preflight, not part of
// Validate or Generate. It asks that action outputs be available on every
// explored control path, including dependencies of eagerly evaluated pure
// blocks. Boolean action outputs are independent unless the same output is
// tested again; relationships hidden in custom Go are not inferred.
//
// Loops, manual Go, unsupported predicates and exhausted exploration are left
// to the existing validator/runtime. This deliberately incomplete check must
// not be used as a guarantee that an arbitrary workflow will execute correctly.
func ValidateOutputAvailability(w Workflow) []Diagnostic {
	if w.GoCode != nil || len(Validate(w)) != 0 {
		return nil
	}
	a := outputAvailability{nodes: map[string]Node{}, catalog: catalogFor(w), data: map[Endpoint]Endpoint{}, control: map[Endpoint]string{}, budget: 4096}
	for _, n := range w.Nodes {
		if loopBlock(n.Block) {
			return nil
		}
		a.nodes[n.ID] = n
	}
	for _, e := range w.Edges {
		if e.Kind == "data" {
			a.data[e.To] = e.From
		} else {
			a.control[e.From] = e.To.Node
		}
	}
	a.visit(w.Entry, map[string]bool{}, map[Endpoint]bool{})
	if a.budget < 0 {
		return nil
	}
	return a.diagnostics
}

type outputAvailability struct {
	nodes       map[string]Node
	catalog     map[string]Block
	data        map[Endpoint]Endpoint
	control     map[Endpoint]string
	budget      int
	diagnostics []Diagnostic
}

func (a *outputAvailability) step() bool {
	a.budget--
	return a.budget >= 0
}

func (a *outputAvailability) visit(id string, ready map[string]bool, facts map[Endpoint]bool) {
	if id == "" || !a.step() {
		return
	}
	n := a.nodes[id]
	for _, p := range a.catalog[n.Block].Inputs {
		input := Endpoint{id, p.Name}
		if source, ok := a.data[input]; ok {
			if missing := a.missing(source.Node, ready, map[string]bool{}); missing != "" {
				d := Diagnostic{id, p.Name, fmt.Sprintf("action %s output is not guaranteed on this control path; execute it before %s or keep this consumer on the branch that executes it", missing, id)}
				for _, previous := range a.diagnostics {
					if previous == d {
						return
					}
				}
				a.diagnostics = append(a.diagnostics, d)
				return // The generated program stops at this failed input.
			}
		}
	}
	ready = maps.Clone(ready)
	ready[id] = true
	if n.Block == "if" {
		a.branch(id, ready, facts)
	} else {
		a.visit(a.control[Endpoint{id, "next"}], ready, facts)
	}
}

func (a *outputAvailability) missing(id string, ready, seen map[string]bool) string {
	if seen[id] {
		return ""
	}
	seen[id] = true
	n := a.nodes[id]
	if !a.catalog[n.Block].Pure {
		if !ready[id] {
			return id
		}
		return ""
	}
	for _, p := range a.catalog[n.Block].Inputs {
		if source, ok := a.data[Endpoint{id, p.Name}]; ok {
			if missing := a.missing(source.Node, ready, seen); missing != "" {
				return missing
			}
		}
	}
	return ""
}

func (a *outputAvailability) branch(id string, ready map[string]bool, facts map[Endpoint]bool) {
	value, atom, supported := a.boolean(Endpoint{id, "condition"}, facts)
	if !supported {
		return // An unmodeled predicate does not establish a feasible path.
	}
	if atom.Node != "" {
		for _, choice := range []bool{false, true} {
			next := maps.Clone(facts)
			next[atom] = choice
			a.branch(id, ready, next)
		}
		return
	}
	port := "false"
	if value {
		port = "true"
	}
	a.visit(a.control[Endpoint{id, port}], ready, facts)
}

// boolean evaluates only literal booleans, stable action outputs and built-in
// Boolean operations. The returned atom is one still-unassigned action output.
// Availability is checked separately, so logical short-circuiting here never
// hides the runtime's eager input reads (notably false AND missing.ok).
func (a *outputAvailability) boolean(input Endpoint, facts map[Endpoint]bool) (bool, Endpoint, bool) {
	if !a.step() {
		return false, Endpoint{}, false
	}
	source, wired := a.data[input]
	if !wired {
		value, ok := a.nodes[input.Node].Inputs[input.Port].(bool)
		return value, Endpoint{}, ok
	}
	n := a.nodes[source.Node]
	if n.Block == "constant" || n.Block == "emit" {
		return a.boolean(Endpoint{n.ID, source.Port}, facts)
	}
	if !a.catalog[n.Block].Pure {
		if value, ok := facts[source]; ok {
			return value, Endpoint{}, true
		}
		return false, source, true
	}
	switch n.Block {
	case "not":
		value, atom, ok := a.boolean(Endpoint{n.ID, "value"}, facts)
		return !value, atom, ok
	case "and", "or":
		left, atom, ok := a.boolean(Endpoint{n.ID, "a"}, facts)
		if !ok || atom.Node != "" {
			return left, atom, ok
		}
		if n.Block == "and" && !left || n.Block == "or" && left {
			return left, Endpoint{}, true
		}
		return a.boolean(Endpoint{n.ID, "b"}, facts)
	}
	return false, Endpoint{}, false
}
