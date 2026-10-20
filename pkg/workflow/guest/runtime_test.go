// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRuntimeNeverInventsActionOutputs(t *testing.T) {
	r := New(strings.Repeat("a", 64))
	r.writer = &bytes.Buffer{}
	if _, err := r.Output("probe", "ok"); err == nil {
		t.Fatal("unexecuted action had an output")
	}
	if err := r.Record("probe", "ping", map[string]any{"ok": false}); err != nil {
		t.Fatal(err)
	}
	value, err := r.Output("probe", "ok")
	if err != nil || value != false {
		t.Fatalf("failed network outcome lost: %v %v", value, err)
	}
	r.Forget("probe")
	if _, err = r.Output("probe", "ok"); err == nil {
		t.Fatal("previous iteration output remained")
	}
}
func TestRuntimeTraceAndLimits(t *testing.T) {
	var output bytes.Buffer
	r := New(strings.Repeat("a", 64))
	r.writer = &output
	if err := r.Record("probe", "http", map[string]any{"ok": false, "error": "connection refused"}); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["schema"] != "debuglet.workflow.v1" || event["status"] != "completed" {
		t.Fatal(event)
	}
	if err := r.Record("large", "emit", map[string]any{"value": strings.Repeat("x", 16385)}); err == nil {
		t.Fatal("unbounded string accepted")
	}
	for i := 0; i < 1000; i++ {
		if err := r.Step(); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Step(); err == nil {
		t.Fatal("unbounded action steps")
	}
}
func TestTypedOperations(t *testing.T) {
	if _, err := Pure("mean", map[string]any{"values": []any{}}); err == nil {
		t.Fatal("empty samples became zero")
	}
	if err := Check(map[string]any{"condition": "true"}, map[string]string{"condition": "boolean"}); err == nil {
		t.Fatal("string silently coerced to boolean")
	}
	out, err := Pure("mean", map[string]any{"values": []any{float64(10), float64(20)}})
	if err != nil || out["value"] != float64(15) {
		t.Fatalf("mean = %v %v", out, err)
	}
	if _, err = Pure("field", map[string]any{"object": map[string]any{}, "name": "missing"}); err == nil {
		t.Fatal("missing field invented")
	}
	out, err = Normalize(map[string]any{"values": []float64{10, 20}, "count": 2})
	if err != nil {
		t.Fatal(err)
	}
	if err = Check(out, map[string]string{"values": "numbers", "count": "number"}); err != nil {
		t.Fatal(err)
	}
}

func TestCustomPanicIsAnError(t *testing.T) {
	_, err := RunCustom(func(map[string]any) (map[string]any, error) { panic("bad sample") }, map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "bad sample") {
		t.Fatalf("panic outcome: %v", err)
	}
}
