// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "time"

const (
	ProfileVersion        = 1
	MaxProfileBytes       = 8 << 20
	MaxProfilesPerAccount = 32
	// ProbeSHA256 identifies the Go 1.25.11 build shipped by the matching
	// dashboard. Clients verify the asset before applying a catalogue entry.
	ProbeSHA256 = "0135f2de557856f013e707d35225d3999895e217e55029c5d83cd5d595ffe91b"
)

// ProfileConfig is reusable: it deliberately contains neither an absolute
// scheduled start nor any payment or account credential. Unknown fields are
// rejected by the API rather than silently retained.
type ProfileConfig struct {
	Version    int                `json:"version"`
	Name       string             `json:"name"`
	Program    ProfileProgram     `json:"program"`
	ExecutorID string             `json:"executor_id"`
	Args       []string           `json:"args"`
	Policy     Policy             `json:"policy"`
	Template   *TemplateReference `json:"template,omitempty"`
}

type ProfileProgram struct {
	SHA256 string `json:"sha256"`
	Wasm   []byte `json:"wasm"`
}

type TemplateReference struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

type Profile struct {
	ID     string        `json:"id"`
	Config ProfileConfig `json:"config"`
}

// ProfileSummary excludes the program and arguments so listing remains small.
type ProfileSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ProgramSHA256 string `json:"program_sha256"`
}

type MeasurementTemplate struct {
	ID                 string            `json:"id"`
	Version            int               `json:"version"`
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	ProgramSHA256      string            `json:"program_sha256"`
	ProgramAsset       string            `json:"program_asset"`
	Arguments          TemplateArguments `json:"arguments"`
	RequiredTransports []string          `json:"required_transports"`
	DefaultPolicy      Policy            `json:"default_policy"`
}

// TemplateArguments is a JSON Schema object for the template's input fields.
// Defaults include only reusable values; destinations require user input.
type TemplateArguments struct {
	Type                 string                      `json:"type"`
	Properties           map[string]TemplateArgument `json:"properties"`
	Required             []string                    `json:"required"`
	AdditionalProperties bool                        `json:"additionalProperties"`
}

type TemplateArgument struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Default     string `json:"default"`
}

// SubmittedConfiguration retains the exact requested settings before policy
// normalization. Program bytes and payment credentials are never copied here.
type SubmittedConfiguration struct {
	Label          string   `json:"label"`
	ProgramName    string   `json:"program_name"`
	RequestedStart *int64   `json:"requested_start"`
	Args           []string `json:"args"`
	Policy         Policy   `json:"policy"`
}

// MaxRunDetailBytes accommodates retained configuration from before profiles
// had their own smaller upload bound, while keeping each response bounded.
const MaxRunDetailBytes = MaxResultBytes

// RunDetail is independent of output size. Unknown actual times and exit codes
// remain null; a reservation is never described as observed execution.
type RunDetail struct {
	Execution  *RunExecution           `json:"execution"`
	RunID      string                  `json:"run_id"`
	ExecutorID string                  `json:"executor_id"`
	BatchID    string                  `json:"batch_id"`
	OrderID    int64                   `json:"order_id"`
	Submitted  *SubmittedConfiguration `json:"submitted"`
	Provenance *ResultProvenance       `json:"provenance"`
	Outcome    ResultOutcome           `json:"outcome"`
	Timing     ResultTiming            `json:"timing"`
	Cost       *RunCost                `json:"cost"`
}

type RunCost struct {
	Currency   string  `json:"currency"`
	Unit       string  `json:"unit"`
	Reserved   string  `json:"reserved"`
	Charged    *string `json:"charged"`
	Settlement string  `json:"settlement"`
}

type MeasurementSummary struct {
	ID             string    `json:"id"`
	Label          string    `json:"label"`
	State          string    `json:"state"`
	Children       int64     `json:"children"`
	ScheduledStart time.Time `json:"scheduled_start"`
}

type MeasurementPage struct {
	Measurements []MeasurementSummary `json:"measurements"`
	Total        int64                `json:"total"`
	Counts       map[string]int64     `json:"counts"`
	Limit        int64                `json:"limit"`
	Offset       int64                `json:"offset"`
}

type Measurement struct {
	ID     string           `json:"id"`
	Runs   []MeasurementRun `json:"runs"`
	Total  int64            `json:"total"`
	Limit  int64            `json:"limit"`
	Offset int64            `json:"offset"`
}

// MeasurementRun is a bounded reference. Load RunDetail for its configuration.
type MeasurementRun struct {
	RunID       string `json:"run_id"`
	ExecutorID  string `json:"executor_id"`
	OrderID     int64  `json:"order_id"`
	State       string `json:"state"`
	Label       string `json:"label"`
	ProgramName string `json:"program_name"`
}

// RunExecution records received executor reports using the dispatcher's clock.
// It does not assert an exact executor start time or network reachability.
type RunExecution struct {
	TimeSource         string     `json:"time_source"`
	StartedObservedAt  *time.Time `json:"started_observed_at"`
	TerminalObservedAt *time.Time `json:"terminal_observed_at"`
	ReportedExitCode   *int32     `json:"reported_exit_code"`
	TCPListener        *string    `json:"tcp_listener"`
	ListenerReady      bool       `json:"listener_ready"`
}
