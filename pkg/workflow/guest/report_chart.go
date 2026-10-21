// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import "fmt"

func validateChart(in map[string]any) error {
	if in["kind"] != "line" && in["kind"] != "bar" {
		return fmt.Errorf("report chart kind must be line or bar")
	}
	rows, err := objectRows(in["rows"])
	if err != nil {
		return err
	}
	if len(rows) < 1 || len(rows) > 256 {
		return fmt.Errorf("report chart requires 1–256 rows")
	}
	for _, axis := range []string{"x", "y"} {
		field := in[axis].(string)
		if field == "" || len(field) > 256 {
			return fmt.Errorf("report chart %s field must contain 1–256 bytes", axis)
		}
		for i, row := range rows {
			value, err := rowField(row, field, i)
			if err != nil {
				return err
			}
			if !Matches(value, "number") {
				return fmt.Errorf("report chart row %d: field %q must be a finite number", i, field)
			}
		}
	}
	return nil
}
