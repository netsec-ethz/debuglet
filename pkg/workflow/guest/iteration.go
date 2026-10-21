// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import "fmt"

// ForEachItems captures the list before its body runs. Loop actions retain the
// normal workflow step budget in addition to this per-list bound.
func ForEachItems(value any) ([]any, error) {
	items, ok := value.([]any)
	if !ok || len(items) > 100 {
		return nil, fmt.Errorf("for each requires a list of at most 100 items")
	}
	if err := checkValue(items, 0); err != nil {
		return nil, err
	}
	return append([]any{}, items...), nil
}
