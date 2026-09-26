// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package ids

import (
	"strings"
	"testing"
)

func TestParseCanonical(t *testing.T) {
	const id = "3f2c1a9e-7b4d-4e6a-9c1b-2d3e4f5a6b7c"
	if parsed, ok := ParseCanonical(id); !ok || parsed.String() != id {
		t.Fatalf("ParseCanonical(%q) = %v, %v", id, parsed, ok)
	}
	for _, value := range []string{
		"",
		"00000000-0000-0000-0000-000000000000",
		strings.ToUpper(id),
		"3F2c1a9e-7b4d-4e6a-9c1b-2d3e4f5a6b7c",
		"{" + id + "}",
		"urn:uuid:" + id,
		strings.ReplaceAll(id, "-", ""),
		id + "0",
	} {
		if _, ok := ParseCanonical(value); ok {
			t.Errorf("ParseCanonical accepted %q", value)
		}
	}
}
