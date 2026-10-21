// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestSelectFieldPreservesValuesAndOrder(t *testing.T) {
	rows := []any{
		map[string]any{"sample": float64(12)},
		map[string]any{"sample": nil},
		map[string]any{"sample": map[string]any{"nested": true}},
	}
	out, err := Pure("select_field", map[string]any{"values": rows, "field": "sample"})
	want := []any{float64(12), nil, map[string]any{"nested": true}}
	if err != nil || !reflect.DeepEqual(out["values"], want) {
		t.Fatalf("selection = %v, %v; want %v", out, err, want)
	}
	out["values"].([]any)[0] = "changed"
	if rows[0].(map[string]any)["sample"] != float64(12) {
		t.Fatal("selection changed the source list")
	}
	out, err = Pure("select_field", map[string]any{"values": []any{}, "field": "sample"})
	if err != nil || !reflect.DeepEqual(out["values"], []any{}) {
		t.Fatalf("empty selection = %v, %v", out, err)
	}
}

func TestFilterRowsOperators(t *testing.T) {
	rows := []any{map[string]any{"sample": float64(1)}, map[string]any{"sample": float64(2)}, map[string]any{"sample": float64(3)}}
	for _, tc := range []struct {
		operator string
		indices  []int
	}{
		{"equals", []int{1}},
		{"not_equals", []int{0, 2}},
		{"greater_than", []int{2}},
		{"less_than", []int{0}},
		{"at_least", []int{1, 2}},
		{"at_most", []int{0, 1}},
	} {
		t.Run(tc.operator, func(t *testing.T) {
			out, err := Pure("filter_rows", map[string]any{"rows": rows, "field": "sample", "operator": tc.operator, "value": float64(2)})
			want := make([]any, 0, len(tc.indices))
			for _, i := range tc.indices {
				want = append(want, rows[i])
			}
			if err != nil || !reflect.DeepEqual(out["rows"], want) {
				t.Fatalf("filter = %v, %v; want %v", out, err, want)
			}
			if len(want) != 0 {
				out["rows"].([]any)[0] = nil
				if rows[tc.indices[0]] == nil {
					t.Fatal("filter reused the input backing array")
				}
			}
		})
	}
}

func TestFilterRowsComparesJSONWithoutCoercion(t *testing.T) {
	rows := []any{
		map[string]any{"sample": "2"},
		map[string]any{"sample": float64(2)},
		map[string]any{"sample": nil},
		map[string]any{"sample": map[string]any{"list": []any{true, float64(2)}}},
	}
	for _, value := range []any{float64(2), nil, map[string]any{"list": []any{true, float64(2)}}} {
		out, err := Pure("filter_rows", map[string]any{"rows": rows, "field": "sample", "operator": "equals", "value": value})
		if err != nil {
			t.Fatal(err)
		}
		got := out["rows"].([]any)
		if len(got) != 1 || !reflect.DeepEqual(got[0].(map[string]any)["sample"], value) {
			t.Fatalf("equality coerced or lost %v: %v", value, got)
		}
	}
	for _, operator := range []string{"equals", "greater_than"} {
		out, err := Pure("filter_rows", map[string]any{"rows": []any{}, "field": "sample", "operator": operator, "value": float64(2)})
		if err != nil || !reflect.DeepEqual(out["rows"], []any{}) {
			t.Fatalf("empty filter = %v, %v", out, err)
		}
	}
}

func TestRowTransformsRejectInvalidRows(t *testing.T) {
	for _, rows := range []any{
		"not a list",
		[]any{nil},
		[]any{float64(1)},
		[]any{map[string]any{"sample": float64(1)}, map[string]any{}},
	} {
		for _, block := range []string{"select_field", "filter_rows"} {
			in := map[string]any{"values": rows, "rows": rows, "field": "sample", "operator": "equals", "value": float64(2)}
			if _, err := Pure(block, in); err == nil {
				t.Errorf("%s accepted invalid rows %v", block, rows)
			}
		}
	}
	for _, operator := range []string{"greater_than", "less_than", "at_least", "at_most"} {
		for _, value := range []any{"2", nil, true} {
			if _, err := Pure("filter_rows", map[string]any{"rows": []any{map[string]any{"sample": float64(1)}}, "field": "sample", "operator": operator, "value": value}); err == nil {
				t.Errorf("%s accepted a nonnumeric comparison value %v", operator, value)
			}
			if _, err := Pure("filter_rows", map[string]any{"rows": []any{map[string]any{"sample": value}}, "field": "sample", "operator": operator, "value": float64(2)}); err == nil {
				t.Errorf("%s accepted a nonnumeric row value %v", operator, value)
			}
		}
	}
	if _, err := Pure("filter_rows", map[string]any{"rows": []any{}, "field": "sample", "operator": "eval", "value": float64(2)}); err == nil {
		t.Fatal("unknown operator accepted on an empty list")
	}
}

func TestRowTransformBounds(t *testing.T) {
	for _, count := range []int{1024, 1025} {
		rows := make([]any, count)
		for i := range rows {
			rows[i] = map[string]any{"sample": float64(i)}
		}
		for _, block := range []string{"select_field", "filter_rows"} {
			_, err := Pure(block, map[string]any{"values": rows, "rows": rows, "field": "sample", "operator": "equals", "value": float64(-1)})
			if (err == nil) != (count == 1024) {
				t.Errorf("%s with %d rows: %v", block, count, err)
			}
		}
	}
}

func TestReportValuesAndEventContract(t *testing.T) {
	for _, tc := range []struct {
		block string
		in    map[string]any
	}{
		{"report_metric", map[string]any{"title": "Mean RTT", "value": float64(12.5), "unit": "ms"}},
		{"report_text", map[string]any{"title": "Summary", "text": "<b>Literal text</b>"}},
		{"report_table", map[string]any{"title": "Samples", "rows": []any{map[string]any{"host": "one", "ms": float64(12.5), "extra": true}}, "columns": []any{"host", "ms"}}},
	} {
		t.Run(tc.block, func(t *testing.T) {
			out, err := Report(tc.block, tc.in)
			if err != nil || !reflect.DeepEqual(out, tc.in) {
				t.Fatalf("report = %v, %v; want %v", out, err, tc.in)
			}
			var trace bytes.Buffer
			r := New(strings.Repeat("a", 64))
			r.writer = &trace
			if err := r.Record("report", tc.block, out); err != nil {
				t.Fatal(err)
			}
			var event struct {
				Schema  string         `json:"schema"`
				Node    string         `json:"node_id"`
				Block   string         `json:"block"`
				Status  string         `json:"status"`
				Outputs map[string]any `json:"outputs"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(trace.Bytes()), &event); err != nil {
				t.Fatal(err)
			}
			if event.Schema != "debuglet.workflow.v1" || event.Node != "report" || event.Block != tc.block || event.Status != "completed" || !reflect.DeepEqual(event.Outputs, tc.in) {
				t.Fatalf("report changed the workflow event contract: %+v", event)
			}
			out["title"] = "changed"
			if tc.in["title"] == "changed" {
				t.Fatal("report output reused the input map")
			}
		})
	}
}

func TestReportsRejectInvalidInputs(t *testing.T) {
	validTable := func() map[string]any {
		return map[string]any{"title": "Rows", "rows": []any{map[string]any{"sample": float64(1)}}, "columns": []any{"sample"}}
	}
	for name, change := range map[string]func(map[string]any){
		"not a list":         func(in map[string]any) { in["rows"] = "rows" },
		"nonobject row":      func(in map[string]any) { in["rows"] = []any{nil} },
		"missing column":     func(in map[string]any) { in["columns"] = []any{"absent"} },
		"no columns":         func(in map[string]any) { in["columns"] = []any{} },
		"empty field name":   func(in map[string]any) { in["columns"] = []any{""}; in["rows"] = []any{map[string]any{"": float64(1)}} },
		"duplicate column":   func(in map[string]any) { in["columns"] = []any{"sample", "sample"} },
		"nonstrings columns": func(in map[string]any) { in["columns"] = []any{float64(1)} },
		"long field name":    func(in map[string]any) { in["columns"] = []any{strings.Repeat("x", 257)} },
		"long title":         func(in map[string]any) { in["title"] = strings.Repeat("x", 16385) },
		"large list":         func(in map[string]any) { in["rows"] = make([]any, 1025) },
	} {
		t.Run(name, func(t *testing.T) {
			in := validTable()
			change(in)
			if _, err := Report("report_table", in); err == nil {
				t.Fatal("accepted invalid report table")
			}
		})
	}
	for _, count := range []int{32, 33} {
		columns := make([]any, count)
		row := map[string]any{}
		for i := range columns {
			name := fmt.Sprintf("column%d", i)
			columns[i], row[name] = name, nil
		}
		_, err := Report("report_table", map[string]any{"title": "Columns", "rows": []any{row}, "columns": columns})
		if (err == nil) != (count == 32) {
			t.Errorf("report with %d columns: %v", count, err)
		}
	}
	if _, err := Report("report_table", map[string]any{"title": "No samples", "rows": []any{}, "columns": []any{"sample"}}); err != nil {
		t.Fatal("empty report table rejected:", err)
	}
	for _, value := range []any{"1", math.NaN(), math.Inf(1)} {
		if _, err := Report("report_metric", map[string]any{"title": "Metric", "value": value, "unit": ""}); err == nil {
			t.Errorf("invalid metric value accepted: %v", value)
		}
	}
	if _, err := Report("report_text", map[string]any{"title": "Text", "text": strings.Repeat("x", 16385)}); err == nil {
		t.Fatal("report text exceeded the string bound")
	}
	if _, err := Report("report_text", map[string]any{"title": "Text"}); err == nil {
		t.Fatal("missing report text accepted")
	}
}

func TestReportFailureUsesExistingTraceLimits(t *testing.T) {
	var trace bytes.Buffer
	r := New(strings.Repeat("a", 64))
	r.writer = &trace
	rows := make([]any, 5)
	for i := range rows {
		rows[i] = map[string]any{"text": strings.Repeat("x", 16384)}
	}
	out, err := Report("report_table", map[string]any{"title": "Large table", "rows": rows, "columns": []any{"text"}})
	if err != nil {
		t.Fatal("individual values should fit their bounds:", err)
	}
	err = r.Record("table", "report_table", out)
	if err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("oversized report event = %v", err)
	}
	if trace.Len() != 0 {
		t.Fatal("partial oversized report was published")
	}
	if err = r.Fail("table", "report_table", err); err == nil {
		t.Fatal("failed report did not return an error")
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(trace.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["status"] != "failed" || event["block"] != "report_table" {
		t.Fatal("report failure did not use the existing failed event:", event)
	}
	if _, err := r.Output("table", "rows"); err == nil {
		t.Fatal("failed report retained successful outputs")
	}
}
