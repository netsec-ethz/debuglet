// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func samplePlotWorkflow() Workflow {
	return Workflow{Version: 1, Name: "Live samples", Entry: "repeat", Nodes: []Node{
		{ID: "repeat", Block: "repeat", Inputs: map[string]any{"count": float64(3)}},
		{ID: "plot", Block: "plot_sample", Inputs: map[string]any{"name": "Sample number"}},
	}, Edges: []Edge{
		edge("control", "repeat", "body", "plot", "in"),
		edge("data", "repeat", "iteration", "plot", "value"),
	}}
}

func TestPlotSampleValidatesLabelsAndNeedsNoHostExtension(t *testing.T) {
	program, err := Generate(samplePlotWorkflow())
	if err != nil {
		t.Fatal(err)
	}
	if program.RequireICMP || program.RequireUDPListener || len(program.RequiredHostFunctions) != 0 || len(program.Destinations) != 0 {
		t.Fatal("plot sample acquired network requirements")
	}
	for _, test := range []struct {
		field string
		value any
	}{
		{"name", ""}, {"name", strings.Repeat("é", 81)}, {"series", strings.Repeat("x", 161)}, {"unit", strings.Repeat("x", 41)},
	} {
		w := samplePlotWorkflow()
		w.Nodes[1].Inputs[test.field] = test.value
		diagnostics := Validate(w)
		found := false
		for _, d := range diagnostics {
			found = found || d.Node == "plot" && d.Port == test.field
		}
		if !found {
			t.Fatalf("invalid %s had no field diagnostic: %+v", test.field, diagnostics)
		}
	}
}

func TestGeneratedPlotSamplesExecuteWASI(t *testing.T) {
	output := executeWorkflowWASI(t, samplePlotWorkflow())
	samples, completed := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		switch event["schema"] {
		case "debuglet.timeseries.v1":
			samples++
			stamp, ok := event["timestamp_ms"].(float64)
			if event["name"] != "Sample number" || event["unit"] != "" || event["series"] != nil || event["value"] != float64(samples) || !ok || stamp < 0 || math.Trunc(stamp) != stamp {
				t.Fatalf("generated sample/defaults changed: %s", line)
			}
		case "debuglet.workflow.v1":
			if event["status"] != "completed" {
				t.Fatalf("unexpected action failure: %s", line)
			}
			if event["block"] == "plot_sample" {
				completed++
			}
		default:
			t.Fatalf("unexpected output: %s", line)
		}
	}
	if samples != 3 || completed != 3 {
		t.Fatalf("got %d samples and %d completed actions", samples, completed)
	}
}
