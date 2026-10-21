// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

type workflowInput struct {
	Workflow workflow.Workflow `json:"workflow"`
}
type savedInput struct {
	Name     string            `json:"name" jsonschema:"A simple name containing letters, digits, hyphens or underscores (no path)."`
	Workflow workflow.Workflow `json:"workflow"`
}
type nameInput struct {
	Name string `json:"name"`
}
type artifactInput struct {
	ArtifactID string `json:"artifact_id"`
}
type metadata struct {
	Kind                  string   `json:"kind,omitempty"`
	ExperimentSHA256      string   `json:"experiment_sha256,omitempty"`
	ArtifactID            string   `json:"artifact_id"`
	BundlePath            string   `json:"bundle_path"`
	WorkflowSHA256        string   `json:"workflow_sha256"`
	WasmSHA256            string   `json:"wasm_sha256"`
	BundleSHA256          string   `json:"bundle_sha256"`
	Destinations          []string `json:"destinations"`
	RequireICMP           bool     `json:"require_icmp"`
	RequireUDPListener    bool     `json:"require_udp_listener,omitempty"`
	RequiredHostFunctions []string `json:"required_host_functions,omitempty"`
}
type store struct {
	root      *os.Root
	directory string
	mu        sync.Mutex
	artifacts map[string]metadata
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$`)

// MCP exposes authoring tools only. Submission and execution remain explicit console actions.
func MCP(ctx context.Context, builder *Builder, directory string) error {
	server, close, err := MCPServer(builder, directory)
	if err != nil {
		return err
	}
	defer close()
	return server.Run(ctx, &mcp.StdioTransport{})
}

func MCPServer(builder *Builder, directory string) (*mcp.Server, func(), error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, err
	}
	files := &store{root: root, directory: directory, artifacts: make(map[string]metadata)}
	server := mcp.NewServer(&mcp.Implementation{Name: "debuglet-studio", Version: "1.0.0"}, &mcp.ServerOptions{Instructions: "Author version-1 Debuglet workflows using catalog primitives. Data edges carry typed values; control edges execute actions. Save the exact workflow for human inspection in the visual editor. Build creates a bundle, but never submits it or spends funds. Custom Go code is visible in the graph and has the same guest permissions as its enclosing program."})
	mcp.AddTool(server, &mcp.Tool{Name: "catalog", Description: "List reusable block types, typed ports and control outputs."}, func(ctx context.Context, req *mcp.CallToolRequest, input struct{}) (*mcp.CallToolResult, map[string]any, error) {
		return nil, map[string]any{"blocks": workflow.Catalog()}, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "validate", Description: "Check the same workflow graph used by the visual editor, including types and bounded control flow."}, func(ctx context.Context, req *mcp.CallToolRequest, input workflowInput) (*mcp.CallToolResult, map[string]any, error) {
		if _, err := boundedWorkflow(input.Workflow); err != nil {
			return nil, nil, err
		}
		diagnostics := workflow.Validate(input.Workflow)
		if diagnostics == nil {
			diagnostics = []workflow.Diagnostic{}
		}
		return nil, map[string]any{"diagnostics": diagnostics}, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "save_workflow", Description: "Save an editable workflow JSON in the configured studio workspace. Replaces a workflow with this simple name; no arbitrary filesystem paths."}, func(ctx context.Context, req *mcp.CallToolRequest, input savedInput) (*mcp.CallToolResult, map[string]any, error) {
		if !safeName.MatchString(input.Name) {
			return nil, nil, errors.New("name must contain 1–48 letters, digits, hyphens or underscores")
		}
		data, err := boundedWorkflow(input.Workflow)
		if err != nil {
			return nil, nil, err
		}
		filename := input.Name + ".workflow.json"
		if err := files.write(filename, data); err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"path": filepath.Join(directory, filename), "workflow_sha256": digest(data)}, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_workflow", Description: "Read a named workflow from the configured studio workspace, for inspection or editing."}, func(ctx context.Context, req *mcp.CallToolRequest, input nameInput) (*mcp.CallToolResult, map[string]any, error) {
		if !safeName.MatchString(input.Name) {
			return nil, nil, errors.New("invalid workflow name")
		}
		file, err := root.Open(input.Name + ".workflow.json")
		if err != nil {
			return nil, nil, err
		}
		defer file.Close()
		wf, err := DecodeWorkflow(file)
		return nil, map[string]any{"workflow": wf}, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "build", Description: "Compile an inspected workflow to a WASI bundle using the configured trusted SDK. Returns artifact metadata and a file to import into the console; does not run the program."}, func(ctx context.Context, req *mcp.CallToolRequest, input workflowInput) (*mcp.CallToolResult, metadata, error) {
		if builder == nil {
			return nil, metadata{}, errors.New("compiler unavailable: configure --sdk")
		}
		bundle, err := builder.Build(ctx, input.Workflow)
		if err != nil {
			return nil, metadata{}, err
		}
		encoded, err := json.Marshal(bundle)
		if err != nil {
			return nil, metadata{}, err
		}
		id := bundle.WorkflowSHA256 + "-" + bundle.WasmSHA256[:12]
		filename := id + ".bundle.json"
		files.mu.Lock()
		defer files.mu.Unlock()
		if _, exists := files.artifacts[id]; !exists && len(files.artifacts) >= 16 {
			return nil, metadata{}, errors.New("this session has 16 artifacts; start a fresh MCP session before building more")
		}
		if err := files.write(filename, encoded); err != nil {
			return nil, metadata{}, err
		}
		meta := metadata{ArtifactID: id, BundlePath: filepath.Join(directory, filename), WorkflowSHA256: bundle.WorkflowSHA256, WasmSHA256: bundle.WasmSHA256, BundleSHA256: digest(encoded), Destinations: bundle.Destinations, RequireICMP: bundle.RequireICMP, RequireUDPListener: bundle.RequireUDPListener, RequiredHostFunctions: bundle.RequiredHostFunctions}
		files.artifacts[id] = meta
		return nil, meta, nil
	})
	experimentTools(server, builder, files)
	mcp.AddTool(server, &mcp.Tool{Name: "read_artifact", Description: "Inspect the graph, generated Go and metadata of a bundle created in this session. WASM bytes remain in the bundle file."}, func(ctx context.Context, req *mcp.CallToolRequest, input artifactInput) (*mcp.CallToolResult, map[string]any, error) {
		files.mu.Lock()
		meta, ok := files.artifacts[input.ArtifactID]
		files.mu.Unlock()
		if !ok {
			return nil, nil, errors.New("artifact was not created by this session")
		}
		file, err := root.Open(filepath.Base(meta.BundlePath))
		if err != nil {
			return nil, nil, err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, MaxExperimentBundleBytes+1))
		if err != nil {
			return nil, nil, err
		}
		if len(data) > MaxExperimentBundleBytes {
			return nil, nil, errors.New("bundle exceeds size limit")
		}
		if digest(data) != meta.BundleSHA256 {
			return nil, nil, errors.New("artifact content changed since build")
		}
		if meta.Kind == "experiment_bundle" {
			result, err := inspectExperimentArtifact(data, meta)
			return nil, result, err
		}
		var bundle Bundle
		if err := json.Unmarshal(data, &bundle); err != nil {
			return nil, nil, err
		}
		if digest(bundle.Wasm) != meta.WasmSHA256 || digest([]byte(bundle.WorkflowJSON)) != meta.WorkflowSHA256 {
			return nil, nil, errors.New("artifact content changed since build")
		}
		if len(bundle.Source)+len(bundle.WorkflowJSON) > 128<<10 {
			return nil, nil, fmt.Errorf("artifact text exceeds the 128 KiB inspection limit; inspect %s in the editor", meta.BundlePath)
		}
		return nil, map[string]any{"metadata": meta, "workflow": bundle.Workflow, "source": bundle.Source}, nil
	})
	return server, func() { _ = root.Close() }, nil
}

func boundedWorkflow(wf workflow.Workflow) ([]byte, error) {
	data, err := json.Marshal(wf)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxWorkflowBytes {
		return nil, errors.New("workflow exceeds the 1 MiB limit")
	}
	return data, nil
}
func (s *store) write(name string, data []byte) error {
	temp, err := os.CreateTemp(s.directory, ".write-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return s.root.Rename(filepath.Base(tempName), name)
}
