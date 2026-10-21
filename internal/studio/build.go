// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package studio builds workflow guests without adding a compiler to the dispatcher.
package studio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

const (
	MaxWorkflowBytes = 1 << 20
	MaxBundleBytes   = 24 << 20
	maxWasmBytes     = 16 << 20
	toolchain        = "go1.26.9"
)

type Bundle struct {
	Version        int               `json:"version"`
	Workflow       workflow.Workflow `json:"workflow"`
	WorkflowJSON   string            `json:"workflow_json"`
	Source         string            `json:"source"`
	WorkflowSHA256 string            `json:"workflow_sha256"`
	WasmSHA256     string            `json:"wasm_sha256"`
	Wasm           []byte            `json:"wasm"`
	Destinations   []string          `json:"destinations"`
	RequireICMP    bool              `json:"require_icmp"`
}

type ValidationError struct {
	Diagnostics []workflow.Diagnostic `json:"diagnostics"`
}

func (e *ValidationError) Error() string { return "workflow has validation errors" }

type Builder struct {
	sdk       string
	goCommand string
	slot      chan struct{}
	hosted    bool
}

// NewBuilder accepts the trusted SDK location chosen by the operator, never by a graph.
func NewBuilder(sdk string) (*Builder, error) {
	path, err := filepath.Abs(sdk)
	if err != nil || sdk == "" {
		return nil, errors.New("--sdk must name the Debuglet source checkout containing pkg/workflow")
	}
	module, err := os.ReadFile(filepath.Join(path, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("read SDK module: %w", err)
	}
	if !strings.HasPrefix(string(module), "module github.com/netsec-ethz/debuglet\n") {
		return nil, errors.New("--sdk must name a Debuglet SDK checkout")
	}
	if _, err := os.Stat(filepath.Join(path, "pkg", "workflow", "guest")); err != nil {
		return nil, errors.New("SDK checkout lacks pkg/workflow/guest; use the same version as dbl-studio")
	}
	goCommand, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("install Go %s to compile workflows: %w", strings.TrimPrefix(toolchain, "go"), err)
	}
	return &Builder{sdk: path, goCommand: goCommand, slot: make(chan struct{}, 1)}, nil
}

func (b *Builder) Build(ctx context.Context, wf workflow.Workflow) (*Bundle, error) {
	if diagnostics := workflow.Validate(wf); len(diagnostics) != 0 {
		return nil, &ValidationError{diagnostics}
	}
	raw, err := json.Marshal(wf)
	if err != nil || len(raw) > MaxWorkflowBytes {
		return nil, errors.New("workflow exceeds the 1 MiB limit or is not valid JSON")
	}
	program, err := workflow.Generate(wf)
	if err != nil {
		return nil, err
	}
	return b.buildProgram(ctx, wf, raw, program)
}

func (b *Builder) buildProgram(ctx context.Context, wf workflow.Workflow, raw []byte, program workflow.Program) (*Bundle, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	select {
	case b.slot <- struct{}{}:
		defer func() { <-b.slot }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "debuglet-workflow-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	env := buildEnv()
	if b.hosted {
		env = append(env, "GOMAXPROCS=2")
	}
	version := exec.CommandContext(ctx, b.goCommand, "env", "GOVERSION")
	version.Env = env
	version.Dir = dir
	actual, err := version.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || strings.TrimSpace(string(actual)) != toolchain {
		return nil, fmt.Errorf("workflow builds require %s installed locally (automatic toolchain downloads are disabled)", toolchain)
	}
	module := "module debuglet.workflow.build\n\ngo 1.26.9\n\nrequire github.com/netsec-ethz/debuglet v0.0.0\nreplace github.com/netsec-ethz/debuglet => " + strconv.Quote(filepath.ToSlash(b.sdk)) + "\n"
	for name, data := range map[string][]byte{"go.mod": []byte(module), "main.go": []byte(program.Source)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return nil, err
		}
	}
	args := []string{"build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-o", "program.wasm"}
	if b.hosted {
		args = append(args, "-p=2")
	}
	command := exec.CommandContext(ctx, b.goCommand, append(args, ".")...)
	command.Dir, command.Env = dir, env
	configureBuildProcess(command)
	output := &boundedOutput{limit: 64 << 10}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("workflow compilation stopped: %w", ctx.Err())
		}
		message := strings.ReplaceAll(output.String(), dir, "<build>")
		message = strings.ReplaceAll(message, b.sdk, "<sdk>")
		if strings.TrimSpace(message) == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("compile workflow: %s", strings.TrimSpace(message))
	}
	file, err := os.Open(filepath.Join(dir, "program.wasm"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	wasm, err := io.ReadAll(io.LimitReader(file, maxWasmBytes+1))
	if err != nil {
		return nil, err
	}
	if len(wasm) > maxWasmBytes {
		return nil, errors.New("compiled workflow exceeds the 16 MiB module limit")
	}
	bundle := &Bundle{Version: 1, Workflow: wf, WorkflowJSON: string(raw), Source: program.Source, WorkflowSHA256: program.WorkflowSHA256, WasmSHA256: digest(wasm), Wasm: wasm, Destinations: program.Destinations, RequireICMP: program.RequireICMP}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxBundleBytes {
		return nil, errors.New("compiled bundle exceeds the 24 MiB limit")
	}
	return bundle, nil
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func buildEnv() []string {
	env := []string{"GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOENV=off", "GOFLAGS="}
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if left := b.limit - b.Len(); left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func DecodeWorkflow(r io.Reader) (workflow.Workflow, error) {
	var wf workflow.Workflow
	data, err := io.ReadAll(io.LimitReader(r, MaxWorkflowBytes+1))
	if err != nil {
		return wf, err
	}
	if len(data) > MaxWorkflowBytes {
		return wf, errors.New("workflow exceeds the 1 MiB limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wf); err != nil {
		return wf, fmt.Errorf("read workflow JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return wf, errors.New("expected one workflow JSON object")
	}
	return wf, nil
}
