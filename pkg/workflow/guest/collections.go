// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode"
)

func collectionList(in map[string]any, name string) ([]any, error) {
	if err := Check(in, map[string]string{name: "any"}); err != nil {
		return nil, err
	}
	items, ok := in[name].([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list", name)
	}
	return items, nil
}

// JSON encoding gives object keys a stable order. Normalize signed zero to
// match JSON numeric equality without changing the original observations.
func collectionKey(value any) string {
	b, _ := json.Marshal(collectionKeyValue(value))
	return string(b)
}

func collectionKeyValue(value any) any {
	switch v := value.(type) {
	case float64:
		if v == 0 {
			return float64(0)
		}
	case []any:
		items := make([]any, len(v))
		for i, item := range v {
			items[i] = collectionKeyValue(item)
		}
		return items
	case map[string]any:
		fields := make(map[string]any, len(v))
		for key, item := range v {
			fields[key] = collectionKeyValue(item)
		}
		return fields
	}
	return value
}

func collectionOutput(name string, value any) (map[string]any, error) {
	out := map[string]any{name: value}
	if err := checkValue(out, 0); err != nil {
		return nil, err
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, fmt.Errorf("collection output exceeds 64 KiB")
	}
	return out, nil
}

func setValues(block string, in map[string]any) (map[string]any, error) {
	leftName := "a"
	if block == "distinct" {
		leftName = "values"
	}
	a, err := collectionList(in, leftName)
	if err != nil {
		return nil, err
	}
	var b []any
	if block != "distinct" {
		b, err = collectionList(in, "b")
		if err != nil {
			return nil, err
		}
	}
	right := make(map[string]bool, len(b))
	for _, value := range b {
		right[collectionKey(value)] = true
	}
	seen := map[string]bool{}
	values := make([]any, 0)
	lists := [][]any{a}
	if block == "set_union" {
		lists = append(lists, b)
	}
	for _, list := range lists {
		for _, value := range list {
			key := collectionKey(value)
			if seen[key] || block == "set_intersection" && !right[key] || block == "set_difference" && right[key] {
				continue
			}
			if len(values) == 1024 {
				return nil, fmt.Errorf("set output exceeds 1024 values")
			}
			seen[key] = true
			values = append(values, value)
		}
	}
	return collectionOutput("values", values)
}

func keyedRows(in map[string]any, listName, fieldName string) ([]any, []string, error) {
	if err := Check(in, map[string]string{listName: "any", fieldName: "string"}); err != nil {
		return nil, nil, err
	}
	rows, err := objectRows(in[listName])
	if err != nil {
		return nil, nil, err
	}
	keys := make([]string, len(rows))
	for i, row := range rows {
		value, err := rowField(row, in[fieldName].(string), i)
		if err != nil {
			return nil, nil, err
		}
		keys[i] = collectionKey(value)
	}
	return rows, keys, nil
}

func groupRows(in map[string]any) (map[string]any, error) {
	rows, keys, err := keyedRows(in, "rows", "field")
	if err != nil {
		return nil, err
	}
	groups := make([]any, 0)
	byKey := map[string]map[string]any{}
	for i, row := range rows {
		group, ok := byKey[keys[i]]
		if !ok {
			group = map[string]any{"key": row.(map[string]any)[in["field"].(string)], "rows": []any{}, "count": float64(0)}
			byKey[keys[i]] = group
			groups = append(groups, group)
		}
		group["rows"] = append(group["rows"].([]any), row)
		group["count"] = group["count"].(float64) + 1
	}
	return collectionOutput("groups", groups)
}

func joinRows(in map[string]any) (map[string]any, error) {
	left, leftKeys, err := keyedRows(in, "left", "left_key")
	if err != nil {
		return nil, err
	}
	right, rightKeys, err := keyedRows(in, "right", "right_key")
	if err != nil {
		return nil, err
	}
	byKey := map[string][]any{}
	for i, row := range right {
		byKey[rightKeys[i]] = append(byKey[rightKeys[i]], row)
	}
	rows := make([]any, 0)
	for i, row := range left {
		for _, match := range byKey[leftKeys[i]] {
			if len(rows) == 1024 {
				return nil, fmt.Errorf("join output exceeds 1024 rows")
			}
			rows = append(rows, map[string]any{"left": row, "right": match})
		}
	}
	return collectionOutput("rows", rows)
}

func addressEndpoint(in map[string]any) (map[string]any, error) {
	if err := Check(in, map[string]string{"address": "string", "port": "number"}); err != nil {
		return nil, err
	}
	address, port := in["address"].(string), in["port"].(float64)
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") && net.ParseIP(address[1:len(address)-1]) != nil {
		address = address[1 : len(address)-1]
	}
	if address == "" || len(address) > 253 || strings.ContainsAny(address, "/?#@[]") || strings.IndexFunc(address, unicode.IsSpace) >= 0 || strings.IndexFunc(address, unicode.IsControl) >= 0 || strings.Contains(address, ":") && net.ParseIP(address) == nil {
		return nil, fmt.Errorf("address must be a hostname or IP without a port or URL")
	}
	if port < 1 || port > 65535 || math.Trunc(port) != port {
		return nil, fmt.Errorf("port must be an integer from 1 to 65535")
	}
	return map[string]any{"target": net.JoinHostPort(address, strconv.Itoa(int(port)))}, nil
}
