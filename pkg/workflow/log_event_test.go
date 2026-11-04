// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func logEventWorkflow() Workflow {
	return Workflow{Version: 1, Name: "Explicit activity", Entry: "repeat", Nodes: []Node{
		{ID: "repeat", Block: "repeat", Inputs: map[string]any{"count": float64(3)}},
		{ID: "branch", Block: "if", Inputs: map[string]any{"condition": false}},
		{ID: "skip", Block: "log_event", Inputs: map[string]any{"message": "Not reached"}},
		{ID: "fault", Block: "log_event", Inputs: map[string]any{"message": "Fault detected", "details": map[string]any{"target": "example.test"}}},
		{ID: "peers", Block: "log_event", Inputs: map[string]any{"message": "Peers triggered"}},
		{ID: "diagnosis", Block: "log_event", Inputs: map[string]any{"message": "Diagnosis ready"}},
	}, Edges: []Edge{
		edge("control", "repeat", "body", "branch", "in"),
		edge("control", "branch", "true", "skip", "in"),
		edge("control", "branch", "false", "fault", "in"),
		edge("control", "fault", "next", "peers", "in"),
		edge("control", "peers", "next", "diagnosis", "in"),
	}}
}

func TestLogEventNeedsNoHostExtensionAndChecksLiteralMessage(t *testing.T) {
	w := logEventWorkflow()
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.RequiredHostFunctions) != 0 || len(p.Destinations) != 0 {
		t.Fatal("log event acquired network requirements")
	}
	w.Nodes[3].Inputs["message"] = " "
	found := false
	for _, d := range Validate(w) {
		found = found || d.Node == "fault" && d.Port == "message"
	}
	if !found {
		t.Fatal("blank message accepted")
	}
}

func TestGeneratedLogEventsExecuteOnlyOnReachedControlPathWASI(t *testing.T) {
	output := executeWorkflowWASI(t, logEventWorkflow())
	want := []string{"Fault detected", "Peers triggered", "Diagnosis ready"}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var event struct {
			Block   string         `json:"block"`
			Outputs map[string]any `json:"outputs"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Block != "log_event" {
			continue
		}
		stamp, ok := event.Outputs["timestamp_ms"].(float64)
		if event.Outputs["message"] != want[count%3] || !ok || stamp <= 0 || math.Trunc(stamp) != stamp {
			t.Fatalf("unexpected event: %s", line)
		}
		if count%3 == 0 && event.Outputs["details"].(map[string]any)["target"] != "example.test" {
			t.Fatal("structured details lost")
		}
		if count%3 != 0 && len(event.Outputs["details"].(map[string]any)) != 0 {
			t.Fatal("optional details default changed")
		}
		count++
	}
	if count != 9 {
		t.Fatalf("got %d explicit events, want three per iteration", count)
	}
}
