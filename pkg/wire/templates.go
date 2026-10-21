// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"encoding/json"
	"time"
)

// Template stores editable source independently of a compiled program or run.
// Document is omitted from list responses.
type Template struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Collection  string          `json:"collection"`
	Kind        string          `json:"kind"`
	Document    json.RawMessage `json:"document,omitempty"`
	Revision    int64           `json:"revision"`
	UpdatedAt   time.Time       `json:"updated_at"`
}
