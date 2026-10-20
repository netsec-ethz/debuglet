// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestCollectionAndTextPrimitives(t *testing.T) {
	cases := []struct {
		block string
		in    map[string]any
		want  any
	}{
		{"stringify_json", map[string]any{"value": map[string]any{"enabled": true}}, `{"enabled":true}`},
		{"list_item", map[string]any{"values": []any{"first", nil, float64(3)}, "index": float64(1)}, nil},
		{"append", map[string]any{"values": []any{}, "value": false}, []any{false}},
		{"concat", map[string]any{"a": "probe ", "b": "complete"}, "probe complete"},
		{"contains", map[string]any{"text": "HTTP/2 200", "substring": "200"}, true},
		{"contains", map[string]any{"text": "HTTP/2 200", "substring": "503"}, false},
		{"split", map[string]any{"text": "a::b::", "separator": "::"}, []any{"a", "b", ""}},
		{"split", map[string]any{"text": "", "separator": ","}, []any{""}},
		{"join", map[string]any{"values": []any{"one", "", "three"}, "separator": ":"}, "one::three"},
		{"join", map[string]any{"values": []any{}, "separator": ","}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.block, func(t *testing.T) {
			out, err := Pure(tc.block, tc.in)
			if err != nil || !reflect.DeepEqual(out["value"], tc.want) {
				t.Fatalf("got %v, %v; want %v", out, err, tc.want)
			}
		})
	}
}

func TestCollectionPrimitivesDoNotMutateInputs(t *testing.T) {
	object := map[string]any{"a": float64(1)}
	out, err := Pure("set_field", map[string]any{"object": object, "name": "a", "value": float64(2)})
	if err != nil {
		t.Fatal(err)
	}
	if object["a"] != float64(1) || out["value"].(map[string]any)["a"] != float64(2) {
		t.Fatalf("object or copy changed incorrectly: %v %v", object, out)
	}

	backing := []any{"original", "untouched", "spare"}
	out, err = Pure("append", map[string]any{"values": backing[:1], "value": "added"})
	if err != nil {
		t.Fatal(err)
	}
	out["value"].([]any)[0] = "edited"
	if !reflect.DeepEqual(backing, []any{"original", "untouched", "spare"}) {
		t.Fatalf("append reused the input backing array: %v", backing)
	}
}

func TestListIndicesMustSelectAnExistingItem(t *testing.T) {
	for _, index := range []float64{-1, 0.5, 2, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := Pure("list_item", map[string]any{"values": []any{"a", "b"}, "index": index}); err == nil {
			t.Errorf("accepted index %v", index)
		}
	}
	if _, err := Pure("list_item", map[string]any{"values": []any{}, "index": float64(0)}); err == nil {
		t.Fatal("selected an item from an empty list")
	}
	for _, block := range []string{"list_item", "append"} {
		if _, err := Pure(block, map[string]any{"values": "not a list", "index": float64(0), "value": nil}); err == nil {
			t.Errorf("%s accepted a string as a list", block)
		}
	}
}

func TestPrimitiveOutputBounds(t *testing.T) {
	maxString := strings.Repeat("x", 16384)
	if _, err := Pure("concat", map[string]any{"a": maxString, "b": ""}); err != nil {
		t.Fatal(err)
	}
	if _, err := Pure("concat", map[string]any{"a": maxString, "b": "x"}); err == nil {
		t.Fatal("concat exceeded the string limit")
	}
	if _, err := Pure("stringify_json", map[string]any{"value": maxString}); err == nil {
		t.Fatal("JSON quoting exceeded the string limit")
	}
	if _, err := Pure("join", map[string]any{"values": []any{maxString}, "separator": ","}); err != nil {
		t.Fatal(err)
	}
	if _, err := Pure("join", map[string]any{"values": []any{maxString, ""}, "separator": ","}); err == nil {
		t.Fatal("join ignored separator bytes")
	}
	for _, count := range []int{1024, 1025} {
		_, err := Pure("split", map[string]any{"text": strings.Repeat(",", count-1), "separator": ","})
		if (err == nil) != (count == 1024) {
			t.Errorf("split into %d values: %v", count, err)
		}
		_, err = Pure("append", map[string]any{"values": make([]any, count-1), "value": nil})
		if (err == nil) != (count == 1024) {
			t.Errorf("append to %d values: %v", count, err)
		}
	}
	if _, err := Pure("split", map[string]any{"text": "abc", "separator": ""}); err == nil {
		t.Fatal("split accepted an empty separator")
	}
	object := map[string]any{}
	for i := 0; i < 1024; i++ {
		object[string(rune(i))] = nil
	}
	if _, err := Pure("set_field", map[string]any{"object": object, "name": "new", "value": nil}); err == nil {
		t.Fatal("set_field exceeded the object limit")
	}
	if len(object) != 1024 {
		t.Fatal("failed set_field changed its input")
	}
	if _, err := Pure("set_field", map[string]any{"object": object, "name": string(rune(0)), "value": true}); err != nil {
		t.Fatal("set_field rejected replacement in a full object:", err)
	}
}

func TestNumericPrimitives(t *testing.T) {
	cases := []struct {
		block string
		in    map[string]any
		want  float64
	}{
		{"multiply", map[string]any{"a": float64(3), "b": float64(4)}, 12},
		{"divide", map[string]any{"a": float64(3), "b": float64(4)}, 0.75},
		{"median", map[string]any{"values": []any{float64(9), float64(1), float64(5)}}, 5},
		{"median", map[string]any{"values": []any{float64(9), float64(1), float64(5), float64(3)}}, 4},
		{"median", map[string]any{"values": []any{math.MaxFloat64, math.MaxFloat64}}, math.MaxFloat64},
		{"percentile", map[string]any{"values": []any{float64(10), float64(0), float64(20)}, "percentile": float64(25)}, 5},
		{"percentile", map[string]any{"values": []any{float64(10), float64(0), float64(20)}, "percentile": float64(0)}, 0},
		{"percentile", map[string]any{"values": []any{float64(10), float64(0), float64(20)}, "percentile": float64(100)}, 20},
		{"percentile", map[string]any{"values": []any{float64(7)}, "percentile": float64(99)}, 7},
		{"percentile", map[string]any{"values": []any{-math.MaxFloat64, math.MaxFloat64}, "percentile": float64(50)}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.block, func(t *testing.T) {
			values, _ := tc.in["values"].([]any)
			before := append([]any(nil), values...)
			out, err := Pure(tc.block, tc.in)
			if err != nil || out["value"] != tc.want {
				t.Fatalf("got %v, %v; want %v", out, err, tc.want)
			}
			if values != nil && !reflect.DeepEqual(values, before) {
				t.Fatal("statistic sorted the input in place")
			}
		})
	}
}

func TestNumericPrimitiveErrors(t *testing.T) {
	for _, block := range []string{"median", "percentile"} {
		if _, err := Pure(block, map[string]any{"values": []any{}, "percentile": float64(50)}); err == nil {
			t.Errorf("%s accepted no samples", block)
		}
	}
	for _, p := range []float64{-1, 101, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := Pure("percentile", map[string]any{"values": []any{float64(1)}, "percentile": p}); err == nil {
			t.Errorf("accepted percentile %v", p)
		}
	}
	for _, tc := range []struct {
		block string
		a, b  float64
	}{
		{"divide", 1, 0},
		{"divide", 1, math.Copysign(0, -1)},
		{"divide", math.MaxFloat64, 0.5},
		{"multiply", math.MaxFloat64, 2},
	} {
		if _, err := Pure(tc.block, map[string]any{"a": tc.a, "b": tc.b}); err == nil {
			t.Errorf("%s(%v, %v) did not reject an invalid result", tc.block, tc.a, tc.b)
		}
	}
}
