// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "time"

const (
	ResultFormat  = "debuglet-result"
	ResultVersion = "1.1"
	// ResultVersion10 files predate vantage_point and remain readable.
	ResultVersion10 = "1.0"
	MaxResultBytes  = 32 << 20
)

// Result is a portable snapshot, not proof that a measurement is true. Missing
// historical admission facts remain nil. Workload outcome and output finality
// are independent observations.
type Result struct {
	Format       string             `json:"format"`
	Version      string             `json:"version"`
	RunID        string             `json:"run_id"`
	ExecutorID   string             `json:"executor_id"`
	Attempt      *ControlBinding    `json:"attempt"`
	Provenance   *ResultProvenance  `json:"provenance"`
	Outcome      ResultOutcome      `json:"outcome"`
	Timing       ResultTiming       `json:"timing"`
	Output       ResultOutput       `json:"output"`
	Verification ResultVerification `json:"verification"`
}

// ResultProvenance is captured once when admission commits. Executor software
// is the executor session's report, not an independent binary attestation.
// AdmittedPolicy describes the dispatched request; actual host policy and
// enforcement are unavailable to this record.
type ResultProvenance struct {
	RunID              string         `json:"run_id"`
	ExecutorID         string         `json:"executor_id"`
	Attempt            ControlBinding `json:"attempt"`
	AdmittedAt         time.Time      `json:"admitted_at"`
	WorkloadSHA256     string         `json:"workload_sha256"`
	Arguments          []string       `json:"arguments"`
	AdmittedPolicy     Policy         `json:"admitted_policy"`
	HostPolicy         string         `json:"host_policy"`
	ExecutorSoftware   *string        `json:"executor_software"`
	DispatcherSoftware *string        `json:"dispatcher_software"`
	DispatcherRevision *string        `json:"dispatcher_revision"`
	CertificateSHA256  *string        `json:"certificate_sha256"`
	VantagePoint       *VantagePoint  `json:"vantage_point"`
}

// Source labels name who asserted a value. None of them means verified: an
// executor claim stays executor-reported however plausible it looks.
const (
	SourceOperator           = "operator"
	SourceExecutorReported   = "executor-reported"
	SourceDispatcherObserved = "dispatcher-observed"
)

// VantagePoint is the admission-time view of where a run executes. It carries
// its own schema version so later facts (ASN, geolocation, reachability) are
// additive. A value that was not recorded is null together with its source.
type VantagePoint struct {
	SchemaVersion int                 `json:"schema_version"`
	Capabilities  VantageCapabilities `json:"capabilities"`
	SourceIP      LabelledString      `json:"source_ip"`
	PublicHost    LabelledString      `json:"public_host"`
}

type LabelledString struct {
	Value  *string `json:"value"`
	Source *string `json:"source"`
}

// VantageCapabilities keeps the last validated capability report even when it
// had outlived its lifetime at admission; Stale says so. ObservedAt is the
// dispatcher's receipt time of that report.
type VantageCapabilities struct {
	Value      *CapabilityReport `json:"value"`
	Source     *string           `json:"source"`
	ObservedAt *time.Time        `json:"observed_at"`
	Stale      *bool             `json:"stale"`
}

type CapabilityReport struct {
	SchemaVersion   int      `json:"schema_version"`
	Protocols       []string `json:"protocols"`
	EnforcementMode string   `json:"enforcement_mode"`
}

type ResultOutcome struct {
	State    string `json:"state"`
	Error    string `json:"error"`
	ExitCode *int64 `json:"exit_code"`
}

// ScheduledStart and ReservedUntil describe admission's reservation, not
// measured execution times. ClockUncertaintyNS is nil when no bound is known.
type ResultTiming struct {
	ObservedAt         time.Time  `json:"observed_at"`
	ScheduledStart     *time.Time `json:"scheduled_start"`
	ReservedUntil      *time.Time `json:"reserved_until"`
	StartedAt          *time.Time `json:"started_at"`
	FinishedAt         *time.Time `json:"finished_at"`
	ClockUncertaintyNS *int64     `json:"clock_uncertainty_ns"`
}

type ResultOutput struct {
	Status  OutputStatus       `json:"status"`
	Entries []LogEntry[[]byte] `json:"entries"`
}

// Attribution identifies the admission source only. It does not authenticate
// packet evidence or establish measurement truth.
type ResultVerification struct {
	Attribution      string `json:"attribution"`
	PacketEvidence   string `json:"packet_evidence"`
	MeasurementTruth string `json:"measurement_truth"`
}
