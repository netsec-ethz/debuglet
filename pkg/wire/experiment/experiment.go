// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package experiment contains readiness data shared by hosts and guests without
// dependencies on host protocol implementations.
package experiment

const (
	MaxExperimentMetadata     = 4096
	MaxExperimentParticipants = 128
)

// Experiment is a one-shot readiness result for one admitted batch. Metadata
// is opaque application data and grants no permission to contact a peer.
type Experiment struct {
	ID           string                  `json:"experiment_id"`
	StartTimeNS  int64                   `json:"start_time_ns"`
	Participants []ExperimentParticipant `json:"participants"`
}

type ExperimentParticipant struct {
	ID         string `json:"id"`
	ExecutorID string `json:"executor_id"`
	Metadata   []byte `json:"metadata"`
	ReadyAtNS  int64  `json:"ready_at_ns"`
}
