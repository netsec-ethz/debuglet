// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package workflow validates visual measurement programs and generates Go WASI guests.
package workflow

// Workflow is the portable source shared by visual and programmatic authors.
type Workflow struct {
	Version      int                `json:"version"`
	Experiment   *ExperimentContext `json:"experiment,omitempty"`
	Name         string             `json:"name"`
	Entry        string             `json:"entry"`
	Nodes        []Node             `json:"nodes"`
	Edges        []Edge             `json:"edges"`
	CustomBlocks []CustomBlock      `json:"custom_blocks,omitempty"`
	Groups       []Group            `json:"groups,omitempty"`
}

// Group folds ordinary nodes in the editor without changing their execution.
type Group struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	NodeIDs  []string  `json:"node_ids"`
	Position *Position `json:"position,omitempty"`
}

type Node struct {
	ID       string         `json:"id"`
	Block    string         `json:"block"`
	Inputs   map[string]any `json:"inputs,omitempty"`
	Position *Position      `json:"position,omitempty"`
}
type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}
type Endpoint struct {
	Node string `json:"node"`
	Port string `json:"port"`
}
type Edge struct {
	Kind string   `json:"kind"`
	From Endpoint `json:"from"`
	To   Endpoint `json:"to"`
}

type Port struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
	Default  any    `json:"default,omitempty"`
}
type Block struct {
	ID             string   `json:"id"`
	Label          string   `json:"label"`
	Category       string   `json:"category"`
	Description    string   `json:"description"`
	Pure           bool     `json:"pure"`
	Inputs         []Port   `json:"inputs"`
	Outputs        []Port   `json:"outputs"`
	ControlOutputs []string `json:"control_outputs"`
}

// CustomBlock is a Go function body, compiled inside the same guest as its callers.
// It is an action: data connections alone never cause it to execute.
type CustomBlock struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Inputs  []Port `json:"inputs"`
	Outputs []Port `json:"outputs"`
	Code    string `json:"code"`
}
type Diagnostic struct {
	Node    string `json:"node,omitempty"`
	Port    string `json:"port,omitempty"`
	Message string `json:"message"`
}
type Program struct {
	Source                string   `json:"source"`
	WorkflowSHA256        string   `json:"workflow_sha256"`
	Destinations          []string `json:"destinations"`
	RequireICMP           bool     `json:"require_icmp"`
	RequireUDPListener    bool     `json:"require_udp_listener,omitempty"`
	RequiredHostFunctions []string `json:"required_host_functions,omitempty"`
}
