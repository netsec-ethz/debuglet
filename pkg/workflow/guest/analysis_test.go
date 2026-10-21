// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"math"
	"reflect"
	"testing"
)

func TestStandardDeviation(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		values     []any
		want       float64
	}{
		{"population", "population", []any{float64(2), float64(4), float64(4), float64(4), float64(5), float64(5), float64(7), float64(9)}, 2},
		{"sample", "sample", []any{float64(1), float64(2), float64(3)}, 1},
		{"constant", "sample", []any{float64(9), float64(9)}, 0},
		{"singleton", "population", []any{float64(9)}, 0},
		{"large offset", "sample", []any{1e15, 1e15 + 1, 1e15 + 2}, 1},
		{"large magnitude", "population", []any{-1e308, 1e308}, 1e308},
		{"small magnitude", "population", []any{-1e-300, 1e-300}, 1e-300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Pure("standard_deviation", map[string]any{"values": tc.values, "mode": tc.mode})
			if err != nil {
				t.Fatal(err)
			}
			got := out["value"].(float64)
			if math.Abs(got-tc.want) > math.Abs(tc.want)*1e-14 || (tc.want == 0 && got != 0) {
				t.Fatalf("standard deviation = %g; want %g", got, tc.want)
			}
		})
	}
	for _, in := range []map[string]any{
		{"values": []any{}, "mode": "population"},
		{"values": []any{float64(1)}, "mode": "sample"},
		{"values": []any{float64(1)}, "mode": "unknown"},
		{"values": []any{math.NaN()}, "mode": "population"},
		{"values": []any{-math.MaxFloat64, math.MaxFloat64}, "mode": "sample"},
	} {
		if _, err := Pure("standard_deviation", in); err == nil {
			t.Errorf("accepted invalid input %v", in)
		}
	}
}

func TestHistogramEdgesAndTailAccounting(t *testing.T) {
	out, err := Pure("histogram", map[string]any{
		"values": []any{float64(-1), float64(0), float64(1), float64(2), float64(3), float64(4), float64(5)},
		"edges":  []any{float64(0), float64(2), float64(4)},
	})
	want := map[string]any{"rows": []any{
		map[string]any{"lower": float64(0), "upper": float64(2), "midpoint": float64(1), "count": float64(2)},
		map[string]any{"lower": float64(2), "upper": float64(4), "midpoint": float64(3), "count": float64(3)},
	}, "underflow": float64(1), "overflow": float64(1), "count": float64(7)}
	if err != nil || !reflect.DeepEqual(out, want) {
		t.Fatalf("histogram = %v, %v; want %v", out, err, want)
	}
	for _, edges := range []any{[]any{}, []any{float64(0)}, []any{float64(1), float64(1)}, []any{float64(2), float64(1)}, []any{float64(0), math.Inf(1)}, make([]any, 258)} {
		if _, err := Pure("histogram", map[string]any{"values": []any{}, "edges": edges}); err == nil {
			t.Errorf("accepted invalid edges %v", edges)
		}
	}
	out, err = Pure("histogram", map[string]any{"values": []any{}, "edges": []any{-math.MaxFloat64, math.MaxFloat64}})
	if err != nil || out["count"] != float64(0) || out["rows"].([]any)[0].(map[string]any)["midpoint"] != float64(0) {
		t.Fatalf("empty/extreme histogram = %v, %v", out, err)
	}
}

func TestSortRowsIsStableAndDoesNotChangeInput(t *testing.T) {
	for _, order := range []string{"ascending", "descending"} {
		rows := []any{map[string]any{"k": float64(2), "id": "first"}, map[string]any{"k": float64(1), "id": "second"}, map[string]any{"k": float64(2), "id": "third"}}
		out, err := Pure("sort_rows", map[string]any{"rows": rows, "field": "k", "order": order})
		if err != nil {
			t.Fatal(err)
		}
		want := []any{rows[1], rows[0], rows[2]}
		if order == "descending" {
			want = []any{rows[0], rows[2], rows[1]}
		}
		if !reflect.DeepEqual(out["rows"], want) {
			t.Fatalf("%s: got %v; want %v", order, out, want)
		}
		out["rows"].([]any)[0] = nil
		if rows[0] == nil || rows[1] == nil || rows[0].(map[string]any)["id"] != "first" {
			t.Fatal("sort mutated input")
		}
	}
	out, err := Pure("sort_rows", map[string]any{"rows": []any{map[string]any{"k": "z"}, map[string]any{"k": "a"}}, "field": "k", "order": "ascending"})
	if err != nil || out["rows"].([]any)[0].(map[string]any)["k"] != "a" {
		t.Fatalf("string sort: %v, %v", out, err)
	}
	for _, rows := range []any{
		[]any{map[string]any{"k": float64(1)}, map[string]any{"k": "2"}},
		[]any{map[string]any{"k": true}}, []any{map[string]any{}}, []any{nil},
	} {
		if _, err := Pure("sort_rows", map[string]any{"rows": rows, "field": "k", "order": "ascending"}); err == nil {
			t.Errorf("accepted rows %v", rows)
		}
	}
}

func TestAnalysisUsesExistingCollectionLimit(t *testing.T) {
	values := make([]any, 1025)
	for i := range values {
		values[i] = float64(i)
	}
	for block, in := range map[string]map[string]any{
		"standard_deviation": {"values": values, "mode": "population"},
		"histogram":          {"values": values, "edges": []any{float64(0), float64(2000)}},
	} {
		if _, err := Pure(block, in); err == nil {
			t.Errorf("%s accepted too many samples", block)
		}
	}
}
