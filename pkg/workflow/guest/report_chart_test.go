// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"math"
	"reflect"
	"testing"
)

func TestReportChartValidatesAxesAndPreservesRows(t *testing.T) {
	valid := map[string]any{"title": "RTT", "rows": []any{map[string]any{"t": float64(1), "rtt": float64(-2), "source": "probe"}}, "x": "t", "y": "rtt", "kind": "line", "x_label": "Time", "y_label": "RTT (ms)"}
	for _, kind := range []string{"line", "bar"} {
		valid["kind"] = kind
		out, err := Report("report_chart", valid)
		if err != nil || !reflect.DeepEqual(out, valid) {
			t.Fatalf("chart changed source data: %v, %v", out, err)
		}
	}
	for field, invalids := range map[string][]any{
		"kind": {"pie", ""}, "x": {"absent", ""}, "y": {"source"},
		"rows": {[]any{}, make([]any, 257), []any{map[string]any{"t": math.NaN(), "rtt": float64(1)}}, []any{map[string]any{"t": float64(1)}}, []any{nil}},
	} {
		for _, invalid := range invalids {
			input := make(map[string]any, len(valid))
			for key, value := range valid {
				input[key] = value
			}
			input[field] = invalid
			if _, err := Report("report_chart", input); err == nil {
				t.Errorf("accepted %s=%v", field, invalid)
			}
		}
	}
}
