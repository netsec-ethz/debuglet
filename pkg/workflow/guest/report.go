// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"fmt"
	"reflect"
)

func objectRows(value any) ([]any, error) {
	rows, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("rows must be a list of objects")
	}
	for i, row := range rows {
		if _, ok := row.(map[string]any); !ok {
			return nil, fmt.Errorf("row %d must be an object", i)
		}
	}
	return rows, nil
}

func rowField(row any, field string, index int) (any, error) {
	value, ok := row.(map[string]any)[field]
	if !ok {
		return nil, fmt.Errorf("row %d: field %q is absent", index, field)
	}
	return value, nil
}

func selectField(in map[string]any) (map[string]any, error) {
	if err := Check(in, map[string]string{"values": "any", "field": "string"}); err != nil {
		return nil, err
	}
	rows, err := objectRows(in["values"])
	if err != nil {
		return nil, err
	}
	values := make([]any, len(rows))
	for i, row := range rows {
		values[i], err = rowField(row, in["field"].(string), i)
		if err != nil {
			return nil, err
		}
	}
	out := map[string]any{"values": values}
	return out, checkValue(out, 0)
}

func filterRows(in map[string]any) (map[string]any, error) {
	if err := Check(in, map[string]string{"rows": "any", "field": "string", "operator": "string", "value": "any"}); err != nil {
		return nil, err
	}
	operator := in["operator"].(string)
	ordering := false
	switch operator {
	case "equals", "not_equals":
	case "greater_than", "less_than", "at_least", "at_most":
		ordering = true
		if !Matches(in["value"], "number") {
			return nil, fmt.Errorf("%s requires a numeric comparison value", operator)
		}
	default:
		return nil, fmt.Errorf("unsupported row filter operator %q", operator)
	}
	rows, err := objectRows(in["rows"])
	if err != nil {
		return nil, err
	}
	filtered := make([]any, 0, len(rows))
	for i, row := range rows {
		value, err := rowField(row, in["field"].(string), i)
		if err != nil {
			return nil, err
		}
		matches := false
		if ordering {
			if !Matches(value, "number") {
				return nil, fmt.Errorf("row %d: %s requires a numeric field", i, operator)
			}
			a, b := value.(float64), in["value"].(float64)
			switch operator {
			case "greater_than":
				matches = a > b
			case "less_than":
				matches = a < b
			case "at_least":
				matches = a >= b
			case "at_most":
				matches = a <= b
			}
		} else {
			matches = reflect.DeepEqual(value, in["value"])
			if operator == "not_equals" {
				matches = !matches
			}
		}
		if matches {
			filtered = append(filtered, row)
		}
	}
	out := map[string]any{"rows": filtered}
	return out, checkValue(out, 0)
}

// Report validates presentation inputs for the ordinary workflow event stream.
// The generated action records the returned outputs through Runtime.Record.
func Report(block string, in map[string]any) (map[string]any, error) {
	var types map[string]string
	switch block {
	case "report_metric":
		types = map[string]string{"title": "string", "value": "number", "unit": "string"}
	case "report_table":
		types = map[string]string{"title": "string", "rows": "any", "columns": "strings"}
	case "report_text":
		types = map[string]string{"title": "string", "text": "string"}
	default:
		return nil, fmt.Errorf("unsupported report block %s", block)
	}
	if err := Check(in, types); err != nil {
		return nil, err
	}
	if block == "report_table" {
		columns := in["columns"].([]any)
		if len(columns) == 0 || len(columns) > 32 {
			return nil, fmt.Errorf("report table requires 1–32 columns")
		}
		seen := make(map[string]bool, len(columns))
		for _, column := range columns {
			field := column.(string)
			if field == "" || len(field) > 256 || seen[field] {
				return nil, fmt.Errorf("report table columns must be distinct nonempty field names of at most 256 bytes")
			}
			seen[field] = true
		}
		rows, err := objectRows(in["rows"])
		if err != nil {
			return nil, err
		}
		for i, row := range rows {
			for _, column := range columns {
				if _, err := rowField(row, column.(string), i); err != nil {
					return nil, err
				}
			}
		}
	}
	out := make(map[string]any, len(types))
	for name := range types {
		out[name] = in[name]
	}
	return out, checkValue(out, 0)
}
