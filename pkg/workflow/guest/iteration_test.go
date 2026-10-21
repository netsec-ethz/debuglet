// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import "testing"

func TestForEachItemsCapturesBoundedList(t *testing.T) {
	for _, value := range []any{nil, "one", float64(2), make([]any, 101)} {
		if _, err := ForEachItems(value); err == nil {
			t.Fatalf("accepted %T", value)
		}
	}
	for _, size := range []int{0, 100} {
		items := make([]any, size)
		snapshot, err := ForEachItems(items)
		if err != nil || len(snapshot) != size {
			t.Fatalf("list size %d: %v", size, err)
		}
		if size > 0 {
			items[0] = "changed"
			if snapshot[0] != nil {
				t.Fatal("list storage was not captured")
			}
		}
	}
}
