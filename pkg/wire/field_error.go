// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

// FieldError identifies a refused request field. Field is a dotted request
// path, Code is a stable reason, and Message is explanatory text, not data to
// parse. OrderID is present when the failure identifies an order in a batch.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
	OrderID *int64 `json:"order_id,omitempty"`
}
