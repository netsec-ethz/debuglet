// Package main provides the repository-only local compatibility witness.
package main

import "github.com/netsec-ethz/debuglet/internal/demo"

type Manifest struct {
	SchemaVersion    int             `json:"schema_version"`
	Environment      string          `json:"environment"`
	Operator         string          `json:"operator"`
	ExecutorID       string          `json:"executor_id"`
	APIBaseURL       string          `json:"api_base_url"`
	Control          ControlManifest `json:"control"`
	Target           TargetManifest  `json:"target"`
	Limits           LimitsManifest  `json:"limits"`
	DeploymentRecord string          `json:"deployment_record"`
	// SourceSHA256 is set by LoadManifest from the original bounded file bytes.
	SourceSHA256 string `json:"-"`
}

type ControlManifest struct {
	GRPCAddr   string `json:"grpc_addr"`
	YamuxAddr  string `json:"yamux_addr"`
	Protection string `json:"protection"`
}

type TargetManifest struct {
	Host string `json:"host"`
}

type LimitsManifest struct {
	ExecutionMS int64 `json:"execution_ms"`
	CeilingBPS  int64 `json:"ceiling_bps"`
	AttemptMS   int64 `json:"attempt_ms"`
}

type Options struct {
	Manifest      Manifest
	Assets        demo.Assets
	ArchiveSHA256 string
	EvidenceDir   string
	DryRun        bool
}

// Pointers retain the distinction between false/empty and not observed.
type Evidence struct {
	SchemaVersion       int                 `json:"schema_version"`
	Environment         string              `json:"environment"`
	ETHTestbed          string              `json:"eth_testbed"`
	Outcome             string              `json:"outcome"`
	Phase               string              `json:"phase"`
	SourceSHA           string              `json:"source_sha"`
	ArchiveSHA256       string              `json:"archive_sha256"`
	ManifestSHA256      string              `json:"manifest_sha256"`
	DispatcherSourceSHA *string             `json:"dispatcher_source_sha"`
	ReportedVersion     *string             `json:"reported_version"`
	ReportedAPIVersion  *string             `json:"reported_api_version"`
	ExecutorID          string              `json:"executor_id"`
	RunID               *string             `json:"run_id"`
	Submission          *SubmissionEvidence `json:"submission"`
	Target              TargetEvidence      `json:"target"`
	Terminal            TerminalEvidence    `json:"terminal"`
	OutputMarkerSeen    *bool               `json:"output_marker_seen"`
	Cleanup             CleanupEvidence     `json:"cleanup"`
	StartedAt           string              `json:"started_at"`
	FinishedAt          *string             `json:"finished_at"`
	Error               *string             `json:"error"`
}

// Unobserved means the run subprocess started but no valid receipt was read;
// its effect is uncertain. Never retry the submission to resolve uncertainty.
type SubmissionEvidence struct {
	State          string  `json:"state"`
	TransactionID  *string `json:"transaction_id"`
	OutcomeUnknown bool    `json:"outcome_unknown"`
}

type TargetEvidence struct {
	Address *string `json:"address"`
	Nonce   *string `json:"nonce"`
	ACK     *bool   `json:"ack"`
}

type TerminalEvidence struct {
	State *string `json:"state"`
	Error *string `json:"error"`
}

type CleanupEvidence struct {
	ChildrenReaped     *bool `json:"children_reaped"`
	StateRemoved       *bool `json:"state_removed"`
	ForcedKills        *int  `json:"forced_kills"`
	RegistryIneligible *bool `json:"registry_ineligible"`
}

// RunReceipt mirrors the installed CLI boundary without importing cmd/dbl.
type RunReceipt struct {
	ID            string `json:"id,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	ExecutorID    string `json:"executor_id"`
	State         string `json:"state"`
	Error         string `json:"error,omitempty"`
}
