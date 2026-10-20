// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

type experimentInput struct {
	Experiment workflow.Experiment `json:"experiment"`
}

func experimentTools(server *mcp.Server, builder *Builder, files *store) {
	mcp.AddTool(server, &mcp.Tool{Name: "validate_experiment", Description: "Validate participant workflows and declared directed message channels. Direct TCP requires pairwise reachability and listener permissions; messages are plaintext."}, func(ctx context.Context, req *mcp.CallToolRequest, input experimentInput) (*mcp.CallToolResult, map[string]any, error) {
		raw, err := json.Marshal(input.Experiment)
		if err != nil {
			return nil, nil, err
		}
		if len(raw) > MaxExperimentBytes {
			return nil, nil, errors.New("experiment exceeds 4 MiB")
		}
		diagnostics := workflow.ValidateExperiment(input.Experiment)
		if diagnostics == nil {
			diagnostics = []workflow.ExperimentDiagnostic{}
		}
		return nil, map[string]any{"diagnostics": diagnostics}, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "build_experiment", Description: "Compile 2–3 participant workflows into a portable experiment bundle, with source, exact shared context and program digests. Does not submit, allocate executors or spend funds. Import the bundle into the experiment editor to inspect or edit it."}, func(ctx context.Context, req *mcp.CallToolRequest, input experimentInput) (*mcp.CallToolResult, metadata, error) {
		if builder == nil {
			return nil, metadata{}, errors.New("compiler unavailable: configure --sdk")
		}
		bundle, err := builder.BuildExperiment(ctx, input.Experiment)
		if err != nil {
			return nil, metadata{}, err
		}
		encoded, err := json.Marshal(bundle)
		if err != nil {
			return nil, metadata{}, err
		}
		hash := digest(encoded)
		id := bundle.ExperimentSHA256 + "-" + hash[:12]
		filename := id + ".experiment-bundle.json"
		files.mu.Lock()
		defer files.mu.Unlock()
		if _, exists := files.artifacts[id]; !exists && len(files.artifacts) >= 16 {
			return nil, metadata{}, errors.New("this session has 16 artifacts; start a fresh MCP session before building more")
		}
		if err := files.write(filename, encoded); err != nil {
			return nil, metadata{}, err
		}
		meta := metadata{Kind: "experiment_bundle", ArtifactID: id, BundlePath: filepath.Join(files.directory, filename), ExperimentSHA256: bundle.ExperimentSHA256, BundleSHA256: hash}
		files.artifacts[id] = meta
		return nil, meta, nil
	})
}

func inspectExperimentArtifact(data []byte, meta metadata) (map[string]any, error) {
	var bundle ExperimentBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}
	if digest([]byte(bundle.ExperimentJSON)) != meta.ExperimentSHA256 {
		return nil, errors.New("experiment content changed since build")
	}
	sources := map[string]string{}
	size := len(bundle.ExperimentJSON)
	for _, p := range bundle.Participants {
		if p.Bundle == nil || digest(p.Bundle.Wasm) != p.Bundle.WasmSHA256 || digest([]byte(p.Bundle.WorkflowJSON)) != p.Bundle.WorkflowSHA256 {
			return nil, errors.New("participant content changed since build")
		}
		sources[p.ID] = p.Bundle.Source
		size += len(p.Bundle.Source)
	}
	if size > 128<<10 {
		return nil, errors.New("artifact text exceeds 128 KiB; inspect the bundle in the experiment editor")
	}
	return map[string]any{"metadata": meta, "experiment": bundle.Experiment, "sources": sources}, nil
}
