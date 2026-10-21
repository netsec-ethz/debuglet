// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"fmt"
	"math"
	"sort"
)

func standardDeviation(in map[string]any) (map[string]any, error) {
	if err := Check(in, map[string]string{"values": "numbers", "mode": "string"}); err != nil {
		return nil, err
	}
	values := in["values"].([]any)
	divisor := len(values)
	switch in["mode"] {
	case "sample":
		divisor--
	case "population":
	default:
		return nil, fmt.Errorf("standard deviation mode must be sample or population")
	}
	if len(values) == 0 || divisor <= 0 {
		return nil, fmt.Errorf("standard deviation needs at least one population value or two sample values")
	}
	lo, hi := values[0].(float64), values[0].(float64)
	for _, value := range values {
		lo, hi = math.Min(lo, value.(float64)), math.Max(hi, value.(float64))
	}
	// Center before scaling to preserve small differences in large-offset data.
	// Scaling keeps squared deviations finite even near the float64 limits.
	center := midpoint(lo, hi)
	scale := math.Max(math.Abs(lo-center), math.Abs(hi-center))
	deviation := float64(0)
	if scale != 0 {
		mean := float64(0)
		for _, value := range values {
			mean += ((value.(float64) - center) / scale) / float64(len(values))
		}
		squares := float64(0)
		for _, value := range values {
			delta := (value.(float64)-center)/scale - mean
			squares += delta * delta
		}
		deviation = math.Sqrt(squares/float64(divisor)) * scale
	}
	out := map[string]any{"value": deviation}
	return out, checkValue(out, 0)
}

func histogram(in map[string]any) (map[string]any, error) {
	if err := Check(in, map[string]string{"values": "numbers", "edges": "numbers"}); err != nil {
		return nil, err
	}
	values, rawEdges := in["values"].([]any), in["edges"].([]any)
	if len(rawEdges) < 2 || len(rawEdges) > 257 {
		return nil, fmt.Errorf("histogram requires 2–257 strictly increasing edges")
	}
	edges := make([]float64, len(rawEdges))
	for i, value := range rawEdges {
		edges[i] = value.(float64)
		if i > 0 && edges[i] <= edges[i-1] {
			return nil, fmt.Errorf("histogram edges must be strictly increasing")
		}
	}
	counts := make([]float64, len(edges)-1)
	underflow, overflow := float64(0), float64(0)
	for _, value := range values {
		n := value.(float64)
		switch {
		case n < edges[0]:
			underflow++
		case n > edges[len(edges)-1]:
			overflow++
		default:
			index := sort.Search(len(edges), func(i int) bool { return edges[i] > n }) - 1
			if index == len(counts) {
				index-- // The final upper edge belongs to the final bin.
			}
			counts[index]++
		}
	}
	rows := make([]any, len(counts))
	for i, count := range counts {
		rows[i] = map[string]any{"lower": edges[i], "upper": edges[i+1], "midpoint": midpoint(edges[i], edges[i+1]), "count": count}
	}
	out := map[string]any{"rows": rows, "underflow": underflow, "overflow": overflow, "count": float64(len(values))}
	return out, checkValue(out, 0)
}

func midpoint(a, b float64) float64 {
	if sum := a + b; !math.IsInf(sum, 0) {
		return sum / 2
	}
	return a/2 + b/2
}

func sortRows(in map[string]any) (map[string]any, error) {
	if err := Check(in, map[string]string{"rows": "any", "field": "string", "order": "string"}); err != nil {
		return nil, err
	}
	field := in["field"].(string)
	if field == "" || len(field) > 256 {
		return nil, fmt.Errorf("sort field must contain 1–256 bytes")
	}
	if in["order"] != "ascending" && in["order"] != "descending" {
		return nil, fmt.Errorf("sort order must be ascending or descending")
	}
	rows, err := objectRows(in["rows"])
	if err != nil {
		return nil, err
	}
	keyType := ""
	for i, row := range rows {
		key, err := rowField(row, field, i)
		if err != nil {
			return nil, err
		}
		kind := "number"
		if _, ok := key.(string); ok {
			kind = "string"
		}
		if !Matches(key, kind) || (keyType != "" && keyType != kind) {
			return nil, fmt.Errorf("sort field must be all finite numbers or all strings")
		}
		keyType = kind
	}
	sorted := append([]any{}, rows...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if in["order"] == "descending" {
			i, j = j, i
		}
		a, b := sorted[i].(map[string]any)[field], sorted[j].(map[string]any)[field]
		if keyType == "string" {
			return a.(string) < b.(string)
		}
		return a.(float64) < b.(float64)
	})
	return map[string]any{"rows": sorted}, nil
}
