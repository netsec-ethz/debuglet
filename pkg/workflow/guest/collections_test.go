// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestSetsCompareJSONWithoutCoercionAndKeepOrder(t *testing.T) {
	object := map[string]any{"b": true, "a": float64(1)}
	a := []any{"first", float64(1), "1", nil, object, "first", math.Copysign(0, -1)}
	b := []any{map[string]any{"a": float64(1), "b": true}, nil, float64(0), "last"}
	for _, tc := range []struct {
		block string
		want  []any
	}{
		{"distinct", []any{"first", float64(1), "1", nil, object, math.Copysign(0, -1)}},
		{"set_union", []any{"first", float64(1), "1", nil, object, math.Copysign(0, -1), "last"}},
		{"set_intersection", []any{nil, object, math.Copysign(0, -1)}},
		{"set_difference", []any{"first", float64(1), "1"}},
	} {
		t.Run(tc.block, func(t *testing.T) {
			out, err := Pure(tc.block, map[string]any{"values": a, "a": a, "b": b})
			if err != nil || !reflect.DeepEqual(out["values"], tc.want) {
				t.Fatalf("got %v, %v; want %v", out, err, tc.want)
			}
			out["values"].([]any)[0] = "replaced"
			if a[0] != "first" || b[0] == "replaced" {
				t.Fatal("result reuses an input list")
			}
		})
	}
}

func TestGroupsAndJoinsPreserveRecordsAndDuplicates(t *testing.T) {
	a := map[string]any{"site": "a", "sample": float64(1)}
	b := map[string]any{"site": "b", "sample": float64(2)}
	c := map[string]any{"site": "a", "sample": float64(3)}
	out, err := Pure("group_by", map[string]any{"rows": []any{a, b, c}, "field": "site"})
	want := []any{
		map[string]any{"key": "a", "rows": []any{a, c}, "count": float64(2)},
		map[string]any{"key": "b", "rows": []any{b}, "count": float64(1)},
	}
	if err != nil || !reflect.DeepEqual(out["groups"], want) {
		t.Fatalf("groups = %v, %v", out, err)
	}
	r1, r2 := map[string]any{"name": "a", "asn": float64(1)}, map[string]any{"name": "a", "asn": float64(2)}
	out, err = Pure("join_rows", map[string]any{"left": []any{a, b, c}, "right": []any{r1, r2}, "left_key": "site", "right_key": "name"})
	want = []any{
		map[string]any{"left": a, "right": r1}, map[string]any{"left": a, "right": r2},
		map[string]any{"left": c, "right": r1}, map[string]any{"left": c, "right": r2},
	}
	if err != nil || !reflect.DeepEqual(out["rows"], want) {
		t.Fatalf("join = %v, %v", out, err)
	}
}

func TestCollectionInputsAndExpansionStayBounded(t *testing.T) {
	rows := make([]any, 33)
	for i := range rows {
		rows[i] = map[string]any{"key": nil}
	}
	for _, tc := range []struct {
		block string
		in    map[string]any
	}{
		{"distinct", map[string]any{"values": "not a list"}},
		{"distinct", map[string]any{"values": make([]any, 1025)}},
		{"distinct", map[string]any{"values": []any{math.NaN()}}},
		{"distinct", map[string]any{"values": []any{strings.Repeat("a", 16384), strings.Repeat("b", 16384), strings.Repeat("c", 16384), strings.Repeat("d", 16384)}}},
		{"group_by", map[string]any{"rows": []any{map[string]any{}}, "field": "absent"}},
		{"group_by", map[string]any{"rows": []any{"not an object"}, "field": "key"}},
		{"join_rows", map[string]any{"left": rows, "right": rows, "left_key": "key", "right_key": "key"}},
		{"join_rows", map[string]any{"left": []any{}, "right": []any{map[string]any{}}, "left_key": "key", "right_key": "absent"}},
	} {
		if _, err := Pure(tc.block, tc.in); err == nil {
			t.Errorf("%s accepted invalid or oversized input", tc.block)
		}
	}
	a, b := make([]any, 1024), []any{"extra"}
	for i := range a {
		a[i] = float64(i)
	}
	if _, err := Pure("set_union", map[string]any{"a": a, "b": b}); err == nil {
		t.Fatal("union exceeded 1024 values")
	}
	if _, err := Pure("distinct", map[string]any{"values": a}); err != nil {
		t.Fatal("1024 distinct values rejected:", err)
	}
	for _, block := range []string{"distinct", "set_union", "set_intersection", "set_difference"} {
		out, err := Pure(block, map[string]any{"values": []any{}, "a": []any{}, "b": []any{}})
		if err != nil || !reflect.DeepEqual(out["values"], []any{}) {
			t.Fatalf("%s empty result = %v, %v", block, out, err)
		}
	}
}

func TestEndpointPreservesIPv6AndRejectsURLsOrInvalidPorts(t *testing.T) {
	for _, tc := range []struct{ address, target string }{
		{"192.0.2.1", "192.0.2.1:443"}, {"example.test", "example.test:443"},
		{"2001:db8::1", "[2001:db8::1]:443"}, {"[2001:db8::1]", "[2001:db8::1]:443"},
	} {
		out, err := Pure("endpoint", map[string]any{"address": tc.address, "port": float64(443)})
		if err != nil || out["target"] != tc.target {
			t.Fatalf("%q = %v, %v", tc.address, out, err)
		}
	}
	for _, address := range []string{"", " example.test", "https://example.test/", "example.test:80", "a\x00b", "user@host"} {
		if _, err := Pure("endpoint", map[string]any{"address": address, "port": float64(443)}); err == nil {
			t.Errorf("accepted address %q", address)
		}
	}
	for _, port := range []float64{0, -1, 65536, 1.5, math.NaN(), math.Inf(1)} {
		if _, err := Pure("endpoint", map[string]any{"address": "example.test", "port": port}); err == nil {
			t.Errorf("accepted port %v", port)
		}
	}
}
