// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package protocol

const (
	OutputVersion       = 1
	MaxOutputFrameBytes = 16 * 1024
	// Logical quota charges include bounded metadata; they are not a bound on
	// SQLite page allocation or filesystem overhead.
	OutputFrameCharge               = 64
	OutputRunCharge                 = 256
	OutputReasonLimit               = "output_limit"
	OutputReasonSpoolLimit          = "spool_limit"
	OutputReasonStorageLimit        = "storage_limit"
	OutputReasonExecutorInterrupted = "executor_interrupted"
	OutputReasonProducerFailed      = "producer_failed"
)

func ValidOutputEnd(end *DebugletOutputEnd) bool {
	if end == nil || end.LastSequence < 0 {
		return false
	}
	switch end.Status {
	case DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE:
		return end.Reason == ""
	case DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED:
		switch end.Reason {
		case OutputReasonLimit, OutputReasonSpoolLimit, OutputReasonStorageLimit, OutputReasonExecutorInterrupted, OutputReasonProducerFailed:
			return true
		}
	}
	return false
}
