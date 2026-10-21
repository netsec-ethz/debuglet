// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

const MaxExperimentBytes = 4 << 20
const MaxExperimentBundleBytes = 32 << 20

type ExperimentBundle struct {
	Version             int                 `json:"version"`
	Kind                string              `json:"kind"`
	Experiment          workflow.Experiment `json:"experiment"`
	ExperimentJSON      string              `json:"experiment_json"`
	ExperimentSHA256    string              `json:"experiment_sha256"`
	Participants        []ParticipantBundle `json:"participants"`
	RequireTCPListener  bool                `json:"require_tcp_listener"`
	ProgramBytes        int                 `json:"program_bytes"`
	EncodedProgramBytes int                 `json:"encoded_program_bytes"`
}
type ParticipantBundle struct {
	ID     string  `json:"id"`
	Label  string  `json:"label,omitempty"`
	Bundle *Bundle `json:"bundle"`
}
type ExperimentValidationError struct {
	Diagnostics []workflow.ExperimentDiagnostic `json:"diagnostics"`
}

func (e *ExperimentValidationError) Error() string { return "experiment has validation errors" }

func DecodeExperiment(r io.Reader) (workflow.Experiment, error) {
	var experiment workflow.Experiment
	data, err := io.ReadAll(io.LimitReader(r, MaxExperimentBytes+1))
	if err != nil {
		return experiment, err
	}
	if len(data) > MaxExperimentBytes {
		return experiment, errors.New("experiment exceeds 4 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&experiment); err != nil {
		return experiment, fmt.Errorf("read experiment JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return experiment, errors.New("expected one experiment JSON object")
	}
	for _, p := range experiment.Participants {
		if _, err := boundedWorkflow(p.Workflow); err != nil {
			return experiment, fmt.Errorf("participant %s: %w", p.ID, err)
		}
	}
	return experiment, nil
}

// BuildExperiment compiles the participants for one existing grouped submission.
// No program is submitted and no permission is inferred from channel metadata.
func (b *Builder) BuildExperiment(ctx context.Context, e workflow.Experiment) (*ExperimentBundle, error) {
	if ds := workflow.ValidateExperiment(e); len(ds) > 0 {
		return nil, &ExperimentValidationError{ds}
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxExperimentBytes {
		return nil, errors.New("experiment exceeds 4 MiB")
	}
	result := &ExperimentBundle{Version: 1, Kind: "experiment_bundle", Experiment: e, ExperimentJSON: string(raw), ExperimentSHA256: digest(raw), RequireTCPListener: true, Participants: []ParticipantBundle{}}
	for _, p := range e.Participants {
		if _, err := boundedWorkflow(p.Workflow); err != nil {
			return nil, fmt.Errorf("participant %s: %w", p.ID, err)
		}
		wf, program, err := workflow.GenerateParticipant(e, p.ID)
		if err != nil {
			return nil, err
		}
		canonical, err := json.Marshal(wf)
		if err != nil {
			return nil, err
		}
		bundle, err := b.buildProgram(ctx, wf, canonical, program)
		if err != nil {
			return nil, fmt.Errorf("participant %s: %w", p.ID, err)
		}
		result.Participants = append(result.Participants, ParticipantBundle{p.ID, p.Label, bundle})
		result.ProgramBytes += len(bundle.Wasm)
		result.EncodedProgramBytes += base64.StdEncoding.EncodedLen(len(bundle.Wasm))
		// Policies, identities and other fields are added by the console; its final
		// exact request-size check remains authoritative for the 32 MiB API limit.
		if result.EncodedProgramBytes >= 32<<20 {
			return nil, errors.New("participant programs exceed the grouped API's 32 MiB request limit; reduce the programs or participant count")
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxExperimentBundleBytes {
		return nil, errors.New("compiled experiment bundle exceeds 32 MiB")
	}
	return result, nil
}
