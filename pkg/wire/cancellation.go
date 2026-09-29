// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "time"

// Cancellation separates a durable request, an executor acknowledgement and
// the immutable run result. An attempted delivery does not confirm receipt.
type Cancellation struct {
	ID              string          `json:"id"`
	RequestID       string          `json:"request_id"`
	ExecutorID      string          `json:"executor_id"`
	OriginalBinding *ControlBinding `json:"original_binding"`
	RequestedAt     time.Time       `json:"requested_at"`
	AttemptedAt     *time.Time      `json:"attempted_at"`
	AcknowledgedAt  *time.Time      `json:"acknowledged_at"`
	CheckedAt       time.Time       `json:"checked_at"`
	Disposition     string          `json:"disposition"`
	Reason          string          `json:"reason"`
	State           string          `json:"state"`
	Error           string          `json:"error"`
}
