// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func reportWorkflow() Workflow {
	return Workflow{Version: 1, Name: "Sample report", Entry: "table", Nodes: []Node{
		{ID: "samples", Block: "constant", Inputs: map[string]any{"value": []any{
			map[string]any{"host": "one", "ok": true, "rtt_ms": float64(10)},
			map[string]any{"host": "two", "ok": false, "rtt_ms": float64(100)},
			map[string]any{"host": "three", "ok": true, "rtt_ms": float64(20)},
		}}},
		{ID: "successful", Block: "filter_rows", Inputs: map[string]any{"field": "ok", "value": true}},
		{ID: "rtts", Block: "select_field", Inputs: map[string]any{"field": "rtt_ms"}},
		{ID: "mean", Block: "mean"},
		{ID: "table", Block: "report_table", Inputs: map[string]any{"title": "Successful samples", "columns": []any{"host", "rtt_ms"}}},
		{ID: "metric", Block: "report_metric", Inputs: map[string]any{"title": "Mean RTT"}},
		{ID: "text", Block: "report_text", Inputs: map[string]any{"title": "Method", "text": "Only successful samples are included."}},
	}, Edges: []Edge{
		edge("data", "samples", "value", "successful", "rows"),
		edge("data", "successful", "rows", "rtts", "values"),
		edge("data", "rtts", "values", "mean", "values"),
		edge("data", "successful", "rows", "table", "rows"),
		edge("data", "mean", "value", "metric", "value"),
		edge("control", "table", "next", "metric", "in"),
		edge("control", "metric", "next", "text", "in"),
	}}
}

func TestReportWorkflowHasNoHostRequirements(t *testing.T) {
	p, err := Generate(reportWorkflow())
	if err != nil {
		t.Fatal(err)
	}
	if p.RequireICMP || p.RequireUDPListener || len(p.RequiredHostFunctions) != 0 || len(p.Destinations) != 0 {
		t.Fatalf("report workflow gained network requirements: %+v", p)
	}
}

func TestGeneratedReportWorkflowExecutesWASI(t *testing.T) {
	if testing.Short() {
		t.Skip("generated WASI program compilation")
	}
	p, err := Generate(reportWorkflow())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "main.go"), filepath.Join(dir, "report.wasm")
	if err := os.WriteFile(source, []byte(p.Source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, source)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOOS=wasip1", "GOARCH=wasm")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile generated WASI report: %v\n%s", err, output)
	}
	wasm, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer r.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if _, err := r.InstantiateWithConfig(ctx, wasm, wazero.NewModuleConfig().WithStdout(&stdout).WithStderr(&stderr)); err != nil {
		t.Fatalf("run generated WASI report: %v\nstderr: %s\nstdout: %s", err, &stderr, &stdout)
	}
	outputs := map[string]map[string]any{}
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var event struct {
			Schema  string         `json:"schema"`
			Node    string         `json:"node_id"`
			Block   string         `json:"block"`
			Status  string         `json:"status"`
			Outputs map[string]any `json:"outputs"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Schema != "debuglet.workflow.v1" || event.Status != "completed" {
			t.Fatalf("unexpected workflow event: %s", line)
		}
		outputs[event.Node] = event.Outputs
		counts[event.Block]++
	}
	wantRows := []any{map[string]any{"host": "one", "ok": true, "rtt_ms": float64(10)}, map[string]any{"host": "three", "ok": true, "rtt_ms": float64(20)}}
	if !reflect.DeepEqual(outputs["table"]["rows"], wantRows) || !reflect.DeepEqual(outputs["table"]["columns"], []any{"host", "rtt_ms"}) {
		t.Fatal("table lost selected rows or explicit columns:", outputs["table"])
	}
	if outputs["metric"]["value"] != float64(15) || outputs["metric"]["unit"] != "" {
		t.Fatal("mean or default metric unit failed:", outputs["metric"])
	}
	if outputs["text"]["text"] != "Only successful samples are included." {
		t.Fatal("report text lost:", outputs["text"])
	}
	for _, block := range []string{"report_table", "report_metric", "report_text"} {
		if counts[block] != 1 {
			t.Errorf("%s executed %d times; want once", block, counts[block])
		}
	}
}
