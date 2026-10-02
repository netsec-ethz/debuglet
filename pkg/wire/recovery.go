// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "time"

// ControlBinding identifies one nonsecret executor control session.
type ControlBinding struct {
	DispatcherIncarnation string `json:"dispatcher_incarnation"`
	SessionID             string `json:"session_id"`
}

// Recovery separates stored outcome from control availability and an optional
// dated executor observation. No classification authorizes replay.
type Recovery struct {
	ID                    string              `json:"id"`
	ExecutorID            string              `json:"executor_id"`
	State                 string              `json:"state"`
	Error                 string              `json:"error"`
	CheckedAt             time.Time           `json:"checked_at"`
	OriginalBinding       *ControlBinding     `json:"original_binding"`
	ControlStatus         string              `json:"control_status"`
	Observation           RecoveryObservation `json:"observation"`
	AllocationReclaimedAt *time.Time          `json:"allocation_reclaimed_at,omitempty"`
}

// RecoveryObservation carries provenance only for a validated executor reply.
// A received reply can already be historical when CurrentAtCheck is false.
type RecoveryObservation struct {
	Classification string            `json:"classification"`
	Observer       *RecoveryObserver `json:"observer"`
	ReceivedAt     *time.Time        `json:"received_at"`
	CurrentAtCheck *bool             `json:"current_at_check"`
	Retained       *RetainedRun      `json:"retained"`
}

type RecoveryObserver struct {
	ExecutorID string         `json:"executor_id"`
	Binding    ControlBinding `json:"binding"`
}

// RetainedRun describes stored metadata, not an executable or terminal result.
// Started records a durable start marker, not proof the guest actually ran.
type RetainedRun struct {
	OriginalBinding *ControlBinding `json:"original_binding"`
	Started         bool            `json:"started"`
	StartedAt       *time.Time      `json:"started_at"`
	StartTime       *time.Time      `json:"start_time"`
}
