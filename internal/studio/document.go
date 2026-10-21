// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

// ValidateDocument preserves Studio's canonical source digests. Bundle
// consistency does not prove that uploaded WASM was compiled from that source.
func ValidateDocument(kind string, document, bundle json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	invalid := func(message string) (json.RawMessage, json.RawMessage, error) {
		return nil, nil, errors.New(message)
	}
	hasBundle := len(bytes.TrimSpace(bundle)) != 0 && !bytes.Equal(bytes.TrimSpace(bundle), []byte("null"))
	if len(bundle) > MaxBundleBytes {
		return invalid("compiled bundle exceeds the 24 MiB limit")
	}
	switch kind {
	case "workflow":
		wf, err := DecodeWorkflow(bytes.NewReader(document))
		if err != nil {
			return invalid("document must be a workflow JSON object of at most 1 MiB")
		}
		program, err := workflow.Generate(wf)
		if err != nil {
			return invalid("document contains an invalid workflow")
		}
		canonical, _ := json.Marshal(wf)
		if !hasBundle {
			return canonical, nil, nil
		}
		var compiled Bundle
		if err := decodeBundle(bundle, &compiled); err != nil {
			return invalid("bundle must be a workflow bundle JSON object")
		}
		if err := validateWorkflowBundle(compiled, canonical, program); err != nil {
			return invalid(err.Error())
		}
		encoded, _ := json.Marshal(compiled)
		return canonical, encoded, nil
	case "experiment":
		experiment, err := DecodeExperiment(bytes.NewReader(document))
		if err != nil {
			return invalid("document must be an experiment JSON object of at most 4 MiB")
		}
		if len(workflow.ValidateExperiment(experiment)) != 0 {
			return invalid("document contains an invalid experiment")
		}
		canonical, _ := json.Marshal(experiment)
		if !hasBundle {
			return canonical, nil, nil
		}
		var compiled ExperimentBundle
		if err := decodeBundle(bundle, &compiled); err != nil {
			return invalid("bundle must be an experiment bundle JSON object")
		}
		if err := validateExperimentBundle(compiled, experiment, canonical); err != nil {
			return invalid(err.Error())
		}
		encoded, _ := json.Marshal(compiled)
		return canonical, encoded, nil
	default:
		return invalid("kind must be workflow or experiment")
	}
}

func decodeBundle(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("expected one bundle JSON object")
	}
	return nil
}

func validateWorkflowBundle(bundle Bundle, canonical []byte, program workflow.Program) error {
	embedded, err := json.Marshal(bundle.Workflow)
	if err != nil || bundle.Version != 1 ||
		!bytes.Equal(embedded, canonical) || bundle.WorkflowJSON != string(canonical) ||
		bundle.WorkflowSHA256 != program.WorkflowSHA256 ||
		!slices.Equal(bundle.Destinations, program.Destinations) || bundle.RequireICMP != program.RequireICMP ||
		bundle.RequireUDPListener != program.RequireUDPListener || !slices.Equal(bundle.RequiredHostFunctions, program.RequiredHostFunctions) ||
		len(bundle.Wasm) < 8 || len(bundle.Wasm) > 16<<20 ||
		!bytes.Equal(bundle.Wasm[:8], []byte{0, 'a', 's', 'm', 1, 0, 0, 0}) ||
		bundle.WasmSHA256 != DocumentDigest(bundle.Wasm) {
		return errors.New("compiled bundle does not match the saved workflow")
	}
	if bundle.Source != program.Source {
		return errors.New("compiled bundle has different generated source; rebuild it with the current Studio and SDK")
	}
	return nil
}

func validateExperimentBundle(bundle ExperimentBundle, experiment workflow.Experiment, canonical []byte) error {
	mismatch := errors.New("compiled bundle does not match the saved experiment")
	embedded, err := json.Marshal(bundle.Experiment)
	if err != nil || bundle.Version != 1 || bundle.Kind != "experiment_bundle" ||
		!bytes.Equal(embedded, canonical) || bundle.ExperimentJSON != string(canonical) ||
		bundle.ExperimentSHA256 != DocumentDigest(canonical) ||
		!bundle.RequireTCPListener || len(bundle.Participants) != len(experiment.Participants) {
		return mismatch
	}
	programBytes, encodedProgramBytes := 0, 0
	for i, participant := range experiment.Participants {
		compiled := bundle.Participants[i]
		if compiled.ID != participant.ID || compiled.Label != participant.Label || compiled.Bundle == nil {
			return mismatch
		}
		wf, program, err := workflow.GenerateParticipant(experiment, participant.ID)
		if err != nil {
			return mismatch
		}
		source, _ := json.Marshal(wf)
		if err := validateWorkflowBundle(*compiled.Bundle, source, program); err != nil {
			return err
		}
		programBytes += len(compiled.Bundle.Wasm)
		encodedProgramBytes += base64.StdEncoding.EncodedLen(len(compiled.Bundle.Wasm))
	}
	if bundle.ProgramBytes != programBytes || bundle.EncodedProgramBytes != encodedProgramBytes {
		return mismatch
	}
	return nil
}

func DocumentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
