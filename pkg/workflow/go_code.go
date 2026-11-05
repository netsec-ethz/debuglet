// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// validateGoCode protects the generated entry point and coordination wrapper.
// Like custom blocks, edited functions still execute in the normal guest sandbox.
func validateGoCode(w Workflow) error {
	code := *w.GoCode
	if len(code) == 0 || len(code) > 256*1024 {
		return fmt.Errorf("functions must contain 1–262144 bytes")
	}
	f, err := parser.ParseFile(token.NewFileSet(), "program.go", "package main\n"+code, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("invalid function declarations: %w", err)
	}
	entry := ""
	for i, node := range w.Nodes {
		if node.ID == w.Entry {
			entry = fmt.Sprintf("run%d", i)
		}
	}
	seen := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			return fmt.Errorf("edit function declarations only; imports, globals and startup stay generated")
		}
		name := fn.Name.Name
		if name == "main" || name == "init" || name == "literal" || name == "runtime" || name == "experiment" {
			return fmt.Errorf("%s is reserved for generated startup and coordination", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate function %s", name)
		}
		seen[name] = true
	}
	if entry != "" && !seen[entry] {
		return fmt.Errorf("keep the entry function %s() error", entry)
	}
	for _, group := range f.Comments {
		for _, comment := range group.List {
			if strings.Contains(comment.Text, "go:") {
				return fmt.Errorf("compiler directives are not supported")
			}
		}
	}
	return nil
}
