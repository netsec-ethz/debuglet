// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestExperimentHTTPUsesStudioSessionAndRejectsUnknownFields(t *testing.T) {
	handler, err := NewHandler(nil, ServerConfig{}, "http://127.0.0.1:8090")
	if err != nil {
		t.Fatal(err)
	}
	session := httptest.NewRecorder()
	handler.ServeHTTP(session, httptest.NewRequest("GET", "http://127.0.0.1:8090/studio/api/session", nil))
	var auth map[string]string
	if err = json.Unmarshal(session.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../../examples/workflows/experiments/three-node.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		token, path string
		body        []byte
		status      int
	}{{"", "validate", body, 403}, {auth["token"], "validate", body, 200}, {auth["token"], "build", body, 503}, {auth["token"], "validate", []byte(`{"version":1,"unknown":true}`), 400}} {
		request := httptest.NewRequest("POST", "http://127.0.0.1:8090/studio/api/experiments/"+test.path, bytes.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Studio-Token", test.token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s: %d %s", test.path, response.Code, response.Body)
		}
	}
	for _, raw := range []string{string(body) + " {}", strings.Repeat(" ", MaxExperimentBytes+1)} {
		if _, err := DecodeExperiment(strings.NewReader(raw)); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}

func TestBuildExperimentPreservesContextAndCompilesEveryParticipant(t *testing.T) {
	if testing.Short() {
		t.Skip("WASI compilation")
	}
	source, err := os.Open("../../examples/workflows/experiments/three-node.json")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	e, err := DecodeExperiment(source)
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuilder(sdk)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	server, closeServer, err := MCPServer(builder, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "experiment-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	built, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "build_experiment", Arguments: experimentInput{e}})
	if err != nil || built.IsError {
		t.Fatalf("build experiment: %v %+v", err, built)
	}
	metaJSON, err := json.Marshal(built.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var meta metadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(meta.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle ExperimentBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.ExperimentSHA256 != digest([]byte(bundle.ExperimentJSON)) || len(bundle.Participants) != 3 || !bundle.RequireTCPListener {
		t.Fatal("incomplete experiment bundle")
	}
	for _, p := range bundle.Participants {
		if p.Bundle.Workflow.Experiment.Fingerprint != bundle.ExperimentSHA256 || p.Bundle.Workflow.Experiment.Participant != p.ID || p.Bundle.WorkflowSHA256 != digest([]byte(p.Bundle.WorkflowJSON)) || p.Bundle.WasmSHA256 != digest(p.Bundle.Wasm) {
			t.Fatalf("participant %s identity mismatch", p.ID)
		}
		if len(p.Bundle.Wasm) < 8 || string(p.Bundle.Wasm[:4]) != "\x00asm" {
			t.Fatalf("participant %s is not WASM", p.ID)
		}
	}
	if len(data) > MaxExperimentBundleBytes || bundle.EncodedProgramBytes >= 32<<20 {
		t.Fatal("oversized experiment")
	}
	read, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "read_artifact", Arguments: artifactInput{meta.ArtifactID}})
	if err != nil || read.IsError {
		t.Fatalf("read experiment artifact: %v %+v", err, read)
	}
}
