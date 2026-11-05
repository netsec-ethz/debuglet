// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestByteLiteralsAndConnectedEncoding(t *testing.T) {
	for _, n := range []Node{
		{ID: "bad", Block: "byte_payload", Inputs: map[string]any{"size_bytes": float64(1)}},
		{ID: "bad", Block: "byte_payload", Inputs: map[string]any{"value": "x", "size_bytes": 1.5}},
		{ID: "bad", Block: "byte_payload", Inputs: map[string]any{"size_bytes": float64(8193)}},
		{ID: "bad", Block: "byte_payload", Inputs: map[string]any{"value": "a", "encoding": "hex"}},
		{ID: "bad", Block: "udp_exchange", Inputs: map[string]any{"target": "127.0.0.1:1234", "payload": "AB==", "encoding": "base64"}},
		{ID: "bad", Block: "tcp_exchange", Inputs: map[string]any{"target": "127.0.0.1:1234", "delimiter": "0", "delimiter_encoding": "hex"}},
		{ID: "bad", Block: "http", Inputs: map[string]any{"url": "http://example.test", "body": "ff 00", "encoding": "hex"}},
	} {
		w := sampleWorkflow()
		w.Nodes = append(w.Nodes, n)
		if ds := Validate(w); len(ds) == 0 {
			t.Fatalf("accepted invalid byte input %+v", n)
		}
	}
	w := sampleWorkflow()
	w.Nodes = append(w.Nodes,
		Node{ID: "encoding", Block: "constant", Inputs: map[string]any{"value": "text"}},
		Node{ID: "payload", Block: "byte_payload", Inputs: map[string]any{"value": "not hex", "size_bytes": float64(0)}},
	)
	w.Edges = append(w.Edges, edge("data", "encoding", "value", "payload", "encoding"))
	if ds := Validate(w); len(ds) != 0 {
		t.Fatalf("connected encoding must be checked at runtime: %v", ds)
	}
}

func TestGeneratedByteAssembly(t *testing.T) {
	if testing.Short() {
		t.Skip("generated program compilation")
	}
	w := Workflow{Version: 1, Name: "Binary assembly", Entry: "result", Nodes: []Node{
		{ID: "pattern", Block: "byte_payload", Inputs: map[string]any{"value": "00ff", "encoding": "hex", "size_bytes": float64(8)}},
		{ID: "fields", Block: "concat", Inputs: map[string]any{"a": "d06c0008"}},
		{ID: "packet", Block: "byte_payload", Inputs: map[string]any{"encoding": "hex"}},
		{ID: "result", Block: "emit", Inputs: map[string]any{"name": "wire_hex"}},
		{ID: "count", Block: "emit", Inputs: map[string]any{"name": "byte_count"}},
	}, Edges: []Edge{
		edge("data", "pattern", "hex", "fields", "b"), edge("data", "fields", "value", "packet", "value"),
		edge("data", "packet", "hex", "result", "value"), edge("data", "packet", "bytes", "count", "value"),
		edge("control", "result", "next", "count", "in"),
	}}
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "main.go")
	if err = os.WriteFile(source, []byte(p.Source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", source)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated program: %v\n%s", err, raw)
	}
	results := map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var event struct {
			Block   string         `json:"block"`
			Outputs map[string]any `json:"outputs"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Block == "emit" {
			results[event.Outputs["name"].(string)] = event.Outputs["value"]
		}
	}
	if results["wire_hex"] != "d06c000800ff00ff00ff00ff" || results["byte_count"] != float64(12) {
		t.Fatal("assembled bytes changed:", results)
	}
}
