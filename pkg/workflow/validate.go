// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"regexp"
	"slices"
	"strings"
)

var identifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
var valueTypes = []string{"string", "number", "boolean", "numbers", "strings", "object", "any"}

// Validate checks the portable graph without compiling or executing custom code.
func Validate(w Workflow) []Diagnostic {
	var ds []Diagnostic
	add := func(node, port, msg string) { ds = append(ds, Diagnostic{node, port, msg}) }
	if w.Version != 1 {
		add("", "", "workflow version must be 1")
	}
	if strings.TrimSpace(w.Name) == "" || len(w.Name) > 128 {
		add("", "", "name must contain 1–128 characters")
	}
	if len(w.Nodes) == 0 || len(w.Nodes) > 128 {
		add("", "", "workflow must contain 1–128 nodes")
		return ds
	}
	if len(w.Edges) > 512 {
		add("", "", "workflow has more than 512 edges")
		return ds
	}
	if len(w.CustomBlocks) > 32 {
		add("", "", "workflow has more than 32 custom blocks")
		return ds
	}
	if len(w.Groups) > 64 {
		add("", "", "workflow has more than 64 groups")
		return ds
	}
	catalog := map[string]Block{}
	for _, b := range Catalog() {
		catalog[b.ID] = b
	}
	for _, b := range w.CustomBlocks {
		if !identifier.MatchString(b.ID) {
			add("", "", "custom block has invalid id: "+b.ID)
			continue
		}
		if _, exists := catalog[b.ID]; exists {
			add("", "", "duplicate or reserved custom block id: "+b.ID)
			continue
		}
		if strings.TrimSpace(b.Label) == "" || len(b.Label) > 128 {
			add("", "", "custom block needs a label of at most 128 characters")
		}
		for _, ports := range [][]Port{b.Inputs, b.Outputs} {
			seen := map[string]bool{}
			if len(ports) > 32 {
				add("", "", "custom block has more than 32 ports")
			}
			for _, p := range ports {
				if !identifier.MatchString(p.Name) || seen[p.Name] {
					add("", "", "invalid or duplicate custom port: "+p.Name)
				}
				seen[p.Name] = true
				if !slices.Contains(valueTypes, p.Type) {
					add("", "", "unsupported port type: "+p.Type)
				}
				if p.Default != nil {
					if !matches(p.Default, p.Type) {
						add("", "", "invalid default for custom port: "+p.Name)
					}
					if err := boundedValue(p.Default, 0); err != nil {
						add("", "", "custom default "+p.Name+": "+err.Error())
					}
				}
			}
		}
		if err := validateCustom(b.Code); err != nil {
			add("", "", fmt.Sprintf("custom block %s: %v", b.ID, err))
		}
		catalog[b.ID] = Block{b.ID, b.Label, "Custom", "", false, b.Inputs, b.Outputs, []string{"next"}}
	}
	nodes := map[string]Node{}
	for _, n := range w.Nodes {
		if !identifier.MatchString(n.ID) {
			add(n.ID, "", "node id must start with a letter and use letters, digits, hyphens or underscores (64 characters maximum)")
		}
		if _, ok := nodes[n.ID]; ok {
			add(n.ID, "", "duplicate node id")
		}
		nodes[n.ID] = n
		b, ok := catalog[n.Block]
		if !ok {
			add(n.ID, "", "unknown block: "+n.Block)
			continue
		}
		for k, v := range n.Inputs {
			p, found := port(b.Inputs, k)
			if !found {
				add(n.ID, k, "unknown input")
				continue
			}
			if !matches(v, p.Type) {
				add(n.ID, k, "expected "+p.Type)
			}
			if err := boundedValue(v, 0); err != nil {
				add(n.ID, k, err.Error())
			}
		}
		if n.Position != nil && (math.IsNaN(n.Position.X) || math.IsInf(n.Position.X, 0) || math.IsNaN(n.Position.Y) || math.IsInf(n.Position.Y, 0)) {
			add(n.ID, "", "position must be finite")
		}
	}
	groupIDs, groupedNodes := map[string]bool{}, map[string]bool{}
	for _, g := range w.Groups {
		if !identifier.MatchString(g.ID) || groupIDs[g.ID] || nodes[g.ID].ID != "" {
			add("", "", "group id must be valid and distinct from node and group ids")
		}
		groupIDs[g.ID] = true
		if strings.TrimSpace(g.Label) == "" || len(g.Label) > 128 {
			add("", "", "group needs a label of at most 128 bytes")
		}
		if len(g.NodeIDs) < 2 || len(g.NodeIDs) > 128 {
			add("", "", "group must contain 2–128 nodes")
		}
		for _, id := range g.NodeIDs {
			if _, exists := nodes[id]; !exists || groupedNodes[id] {
				add(id, "", "group members must be existing nodes and belong to only one group")
			}
			groupedNodes[id] = true
		}
		if g.Position != nil && (math.IsNaN(g.Position.X) || math.IsInf(g.Position.X, 0) || math.IsNaN(g.Position.Y) || math.IsInf(g.Position.Y, 0)) {
			add("", "", "group position must be finite")
		}
	}
	entry, ok := nodes[w.Entry]
	if !ok {
		add("", "", "entry must name a node")
	} else if catalog[entry.Block].Pure {
		add(entry.ID, "", "entry must be an action or control block")
	}
	connected := map[Endpoint]bool{}
	controls := map[Endpoint]bool{}
	dataAdj, controlAdj := map[string][]string{}, map[string][]string{}
	for _, e := range w.Edges {
		source, sok := nodes[e.From.Node]
		target, tok := nodes[e.To.Node]
		if !sok || !tok {
			add(e.To.Node, e.To.Port, "edge refers to a missing node")
			continue
		}
		sb, tb := catalog[source.Block], catalog[target.Block]
		switch e.Kind {
		case "data":
			sp, spok := port(sb.Outputs, e.From.Port)
			tp, tpok := port(tb.Inputs, e.To.Port)
			if !spok {
				add(source.ID, e.From.Port, "unknown output")
			}
			if !tpok {
				add(target.ID, e.To.Port, "unknown input")
			}
			if spok && tpok && sp.Type != tp.Type && sp.Type != "any" && tp.Type != "any" {
				add(target.ID, e.To.Port, "cannot connect "+sp.Type+" to "+tp.Type)
			}
			if connected[e.To] {
				add(target.ID, e.To.Port, "input has multiple connections")
			}
			if _, ok := target.Inputs[e.To.Port]; ok {
				add(target.ID, e.To.Port, "connected input must not also have a literal")
			}
			connected[e.To] = true
			dataAdj[source.ID] = append(dataAdj[source.ID], target.ID)
		case "control":
			if sb.Pure || !slices.Contains(sb.ControlOutputs, e.From.Port) {
				add(source.ID, e.From.Port, "unknown control output")
			}
			if tb.Pure || e.To.Port != "in" {
				add(target.ID, e.To.Port, "control edges must enter an action's in port")
			}
			if controls[e.From] {
				add(source.ID, e.From.Port, "control output has multiple connections; use an explicit branch")
			}
			controls[e.From] = true
			controlAdj[source.ID] = append(controlAdj[source.ID], target.ID)
		default:
			add(target.ID, e.To.Port, "edge kind must be data or control")
		}
	}
	for _, n := range w.Nodes {
		b, ok := catalog[n.Block]
		if !ok {
			continue
		}
		for _, p := range b.Inputs {
			_, literal := n.Inputs[p.Name]
			if p.Required && !literal && !connected[Endpoint{n.ID, p.Name}] {
				add(n.ID, p.Name, "required input is missing")
			}
		}
		for _, field := range []string{"count", "timeout_ms", "duration_ms"} {
			v, ok := n.Inputs[field]
			if !ok {
				continue
			}
			number, isNumber := asNumber(v)
			if !isNumber {
				continue
			}
			if field == "count" && (n.Block == "repeat" || n.Block == "ping") {
				max := float64(100)
				if n.Block == "ping" {
					max = 10
				}
				if number < 1 || number > max || math.Trunc(number) != number {
					add(n.ID, field, fmt.Sprintf("must be an integer from 1 to %.0f", max))
				}
			}
			if field == "timeout_ms" && (number < 1 || number > 60000 || math.Trunc(number) != number) {
				add(n.ID, field, "must be an integer between 1 and 60000 ms")
			}
			if field == "duration_ms" && (number < 0 || number > 60000) {
				add(n.ID, field, "must be between 0 and 60000 ms")
			}
		}
		validateMeasurementInputs(n, add)
	}
	if hasCycle(dataAdj) {
		add("", "", "data connections contain a cycle")
	}
	if hasCycle(controlAdj) {
		add("", "", "control connections contain a cycle; use Repeat for bounded repetition")
	} else {
		for _, n := range w.Nodes {
			if n.Block != "repeat" {
				continue
			}
			var body, done string
			for _, e := range w.Edges {
				if e.Kind == "control" && e.From.Node == n.ID {
					if e.From.Port == "body" {
						body = e.To.Node
					}
					if e.From.Port == "done" {
						done = e.To.Node
					}
				}
			}
			if body == "" {
				add(n.ID, "body", "repeat needs a body connection")
				continue
			}
			inside := reachable(body, controlAdj)
			after := reachable(done, controlAdj)
			if inside[w.Entry] {
				add(n.ID, "body", "workflow entry cannot be inside a repeat body")
			}
			for id := range inside {
				if after[id] {
					add(n.ID, "body", "repeat body must end before the done continuation")
					break
				}
			}
			for _, e := range w.Edges {
				if e.Kind == "control" && inside[e.To.Node] && !inside[e.From.Node] && !(e.From.Node == n.ID && e.From.Port == "body") {
					add(n.ID, "body", "repeat body cannot have control entry from outside its body")
					break
				}
			}
		}
	}
	return ds
}

func port(ports []Port, name string) (Port, bool) {
	for _, p := range ports {
		if p.Name == name {
			return p, true
		}
	}
	return Port{}, false
}
func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, e := n.Float64()
		return f, e == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
}
func matches(v any, kind string) bool {
	switch kind {
	case "any":
		return true
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := asNumber(v)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "numbers", "strings":
		a, ok := v.([]any)
		if !ok {
			return false
		}
		typ := "number"
		if kind == "strings" {
			typ = "string"
		}
		for _, item := range a {
			if !matches(item, typ) {
				return false
			}
		}
		return true
	}
	return false
}
func boundedValue(v any, depth int) error {
	if depth > 16 {
		return fmt.Errorf("value is nested more than 16 levels")
	}
	switch x := v.(type) {
	case string:
		if len(x) > 16384 {
			return fmt.Errorf("string exceeds 16 KiB")
		}
	case []any:
		if len(x) > 1024 {
			return fmt.Errorf("list exceeds 1024 values")
		}
		for _, v := range x {
			if err := boundedValue(v, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(x) > 1024 {
			return fmt.Errorf("object exceeds 1024 fields")
		}
		for k, v := range x {
			if len(k) > 256 {
				return fmt.Errorf("object field name exceeds 256 bytes")
			}
			if err := boundedValue(v, depth+1); err != nil {
				return err
			}
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("value is not JSON: %w", err)
	}
	if len(b) > 65536 {
		return fmt.Errorf("value exceeds 64 KiB")
	}
	return nil
}
func hasCycle(adj map[string][]string) bool {
	state := map[string]int{}
	var visit func(string) bool
	visit = func(n string) bool {
		if state[n] == 1 {
			return true
		}
		if state[n] == 2 {
			return false
		}
		state[n] = 1
		for _, child := range adj[n] {
			if visit(child) {
				return true
			}
		}
		state[n] = 2
		return false
	}
	for n := range adj {
		if visit(n) {
			return true
		}
	}
	return false
}
func reachable(start string, adj map[string][]string) map[string]bool {
	seen := map[string]bool{}
	var visit func(string)
	visit = func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		for _, child := range adj[n] {
			visit(child)
		}
	}
	visit(start)
	return seen
}
func validateCustom(body string) error {
	if len(body) == 0 || len(body) > 32768 {
		return fmt.Errorf("code must contain 1–32768 bytes")
	}
	f, err := parser.ParseFile(token.NewFileSet(), "custom.go", "package main\nfunc custom(inputs map[string]any) (map[string]any,error) {\n"+body+"\n}", parser.ParseComments)
	if err != nil {
		return fmt.Errorf("invalid Go function body: %w", err)
	}
	if len(f.Decls) != 1 {
		return fmt.Errorf("code must be a single function body")
	}
	fn, ok := f.Decls[0].(*ast.FuncDecl)
	if !ok || fn.Name.Name != "custom" {
		return fmt.Errorf("code must be a single function body")
	}
	for _, group := range f.Comments {
		for _, c := range group.List {
			if strings.Contains(c.Text, "go:") {
				return fmt.Errorf("compiler directives are not supported")
			}
		}
	}
	return nil
}
