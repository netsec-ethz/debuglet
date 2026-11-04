// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLogEventRejectsInvalidDynamicValues(t *testing.T) {
	for _, in := range []map[string]any{
		{"message": "", "details": nil},
		{"message": "  \n", "details": nil},
		{"message": strings.Repeat("é", 513), "details": nil},
		{"message": string([]byte{0xff}), "details": nil},
		{"message": float64(1), "details": nil},
		{"message": "Fault detected", "details": strings.Repeat("x", 8192)},
		{"message": "Fault detected", "details": make([]any, 1025)},
	} {
		if _, err := LogEvent(in); err == nil {
			t.Fatal("invalid log event accepted")
		}
	}
}

func TestLogEventsSurvivePeriodicTraceSuppressionAndKeepOutputLimits(t *testing.T) {
	r, _ := scheduledRuntime()
	var out bytes.Buffer
	r.writer = &out
	in := everyInputs()
	in["duration_ms"] = float64(100000)
	err := r.Every(in, func(v map[string]any) error {
		for i := 0; i < 20; i++ {
			if err := r.Record("math", "add", map[string]any{"value": v["iteration"]}); err != nil {
				return err
			}
		}
		values, err := LogEvent(map[string]any{"message": "Diagnosis ready", "details": map[string]any{"iteration": v["iteration"]}})
		if err != nil {
			return err
		}
		return r.Record("diagnosis", "log_event", values)
	})
	if err != nil {
		t.Fatal(err)
	}
	events := 0
	for _, line := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n")) {
		var record struct {
			Block   string         `json:"block"`
			Outputs map[string]any `json:"outputs"`
		}
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		if record.Block == "log_event" {
			events++
			if record.Outputs["details"].(map[string]any)["iteration"] != float64(events) {
				t.Fatal("repeated event was omitted or reordered")
			}
		}
	}
	if events != 100 || r.events != 164 {
		t.Fatalf("events=%d total records=%d", events, r.events)
	}
	values, err := LogEvent(map[string]any{"message": "Fault detected", "details": nil})
	if err != nil {
		t.Fatal(err)
	}
	r.events = 100000
	if err := r.Record("fault", "log_event", values); err == nil {
		t.Fatal("periodic event limit missing")
	}
	r.events = 0
	r.bytes = 32 * 1024 * 1024
	if err := r.Record("fault", "log_event", values); err == nil {
		t.Fatal("periodic byte limit missing")
	}
}
