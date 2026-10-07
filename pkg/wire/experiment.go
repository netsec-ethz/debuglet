// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "github.com/netsec-ethz/debuglet/pkg/wire/experiment"

const (
	MaxExperimentMetadata     = experiment.MaxExperimentMetadata
	MaxExperimentParticipants = experiment.MaxExperimentParticipants
)

// Experiment is a one-shot readiness result for one admitted batch. Metadata
// is opaque application data and grants no permission to contact a peer.
type Experiment = experiment.Experiment

type ExperimentParticipant = experiment.ExperimentParticipant
