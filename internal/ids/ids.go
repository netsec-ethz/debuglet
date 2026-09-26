// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package ids parses the identifiers the dispatcher and executor exchange.
package ids

import "github.com/google/uuid"

// ParseCanonical accepts only the spelling uuid.UUID.String produces: 36
// lowercase hyphenated hex characters. It refuses the nil UUID and the
// uppercase, braced, urn:uuid: and unhyphenated spellings uuid.Parse would
// also read, so every accepted ID has exactly one spelling.
func ParseCanonical(value string) (uuid.UUID, bool) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return uuid.Nil, false
	}
	return id, true
}
