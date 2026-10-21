// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import "testing"

func TestGeneratedAnalysisChartExecutesWASI(t *testing.T) {
	w := Workflow{Version: 1, Name: "Distribution report", Entry: "chart", Nodes: []Node{
		{ID: "samples", Block: "constant", Inputs: map[string]any{"value": []any{float64(1), float64(2), float64(3)}}},
		{ID: "spread", Block: "standard_deviation"},
		{ID: "bins", Block: "histogram", Inputs: map[string]any{"edges": []any{float64(0), float64(2), float64(4)}}},
		{ID: "sorted", Block: "sort_rows", Inputs: map[string]any{"field": "midpoint", "order": "descending"}},
		{ID: "chart", Block: "report_chart", Inputs: map[string]any{"title": "RTT distribution", "x": "midpoint", "y": "count", "kind": "bar"}},
		{ID: "metric", Block: "report_metric", Inputs: map[string]any{"title": "Sample standard deviation", "unit": "ms"}},
	}, Edges: []Edge{
		edge("data", "samples", "value", "spread", "values"),
		edge("data", "samples", "value", "bins", "values"),
		edge("data", "bins", "rows", "sorted", "rows"),
		edge("data", "sorted", "rows", "chart", "rows"),
		edge("data", "spread", "value", "metric", "value"),
		edge("control", "chart", "next", "metric", "in"),
	}}
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if p.RequireICMP || p.RequireUDPListener || len(p.RequiredHostFunctions) > 0 || len(p.Destinations) > 0 {
		t.Fatal("analysis requested network capabilities")
	}
	outputs, counts := executeReportWorkflow(t, w)
	chart := outputs["chart"]
	rows := chart["rows"].([]any)
	if len(rows) != 2 || rows[0].(map[string]any)["midpoint"] != float64(3) || rows[0].(map[string]any)["count"] != float64(2) || rows[1].(map[string]any)["count"] != float64(1) {
		t.Fatal("histogram or stable sort lost samples:", rows)
	}
	if outputs["metric"]["value"] != float64(1) || chart["x_label"] != "" || chart["y_label"] != "" || counts["report_chart"] != 1 {
		t.Fatalf("analysis/report outputs or defaults: %v", outputs)
	}
}
