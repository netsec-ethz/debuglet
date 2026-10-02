// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

// RetryLink identifies an explicit new attempt. Reusing RequestID with the same
// parent and frozen request recovers the attempt; a new ID requests new work.
type RetryLink struct {
	ParentRunID string `json:"parent_run_id"`
	RequestID   string `json:"request_id"`
}

type RetryReceipt struct {
	RetryLink
	RunID string `json:"run_id,omitempty"`
}
