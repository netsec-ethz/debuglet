// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// ExperimentDefinition is a reproducible batch. WASM paths are local to the
// submitting process; SHA256 may be omitted initially and is filled in the receipt.
type ExperimentDefinition struct {
	Participants []ExperimentRun `json:"participants"`
}

// ExperimentRun binds a manifest entry to its admitted run. A definition omits
// RunID; a submission receipt retains the input, digest and assigned run ID.
type ExperimentRun struct {
	OrderID    int64    `json:"order_id"`
	ExecutorID string   `json:"executor_id"`
	WASMPath   string   `json:"wasm_path"`
	SHA256     string   `json:"sha256"`
	Args       []string `json:"args"`
	Policy     Policy   `json:"policy"`
	RunID      string   `json:"run_id,omitempty"`
}

type ExperimentSubmission struct {
	ExperimentID string          `json:"experiment_id"`
	Participants []ExperimentRun `json:"participants"`
}

type ExperimentResults struct {
	Submission ExperimentSubmission `json:"submission"`
	Results    []Result             `json:"results"`
}

// SubmitExperimentTEST submits one existing TEST batch. Its transaction is the
// experiment identity, and each OrderID identifies a member within that batch.
// A supplied digest must match before any network request. On submission errors
// the returned receipt preserves known identities; the error's outcome-unknown
// classification still applies. Never retry an uncertain submission blindly.
func (c *Client) SubmitExperimentTEST(ctx context.Context, def ExperimentDefinition) (ExperimentSubmission, error) {
	receipt := ExperimentSubmission{Participants: append([]ExperimentRun(nil), def.Participants...)}
	requests := make([]Request, len(receipt.Participants))
	for i := range receipt.Participants {
		p := &receipt.Participants[i]
		if p.RunID != "" {
			return receipt, errors.New("client: definition already contains a run id")
		}
		wasm, err := os.ReadFile(p.WASMPath)
		if err != nil {
			return receipt, fmt.Errorf("participant %d: %w", p.OrderID, err)
		}
		digest := sha256.Sum256(wasm)
		hash := hex.EncodeToString(digest[:])
		if p.SHA256 != "" && p.SHA256 != hash {
			return receipt, fmt.Errorf("participant %d: WASM SHA256 mismatch", p.OrderID)
		}
		p.SHA256 = hash
		p.Args = append([]string{}, p.Args...)
		p.Policy.Addresses = append([]string{}, p.Policy.Addresses...)
		requests[i] = Request{OrderID: p.OrderID, ExecutorID: p.ExecutorID, Wasm: wasm, Args: p.Args, Policy: p.Policy}
	}
	batch, err := Prepare(requests)
	if err != nil {
		return receipt, err
	}
	submission, err := c.SubmitTEST(ctx, batch)
	if err != nil {
		var se *SubmissionError
		if errors.As(err, &se) {
			submission = Submission{TransactionID: se.TransactionID, IDs: se.AdmittedIDs}
		}
	}
	receipt.ExperimentID = submission.TransactionID
	if len(submission.IDs) == len(receipt.Participants) {
		for i, id := range submission.IDs {
			receipt.Participants[i].RunID = id
		}
	}
	return receipt, err
}

// ExportExperiment groups existing result snapshots in manifest order. It does
// not wait for completion. On error it returns the successfully read prefix.
func (c *Client) ExportExperiment(ctx context.Context, receipt ExperimentSubmission) (ExperimentResults, error) {
	group := ExperimentResults{Submission: receipt, Results: []Result{}}
	if err := c.checkExperimentReceipt(ctx, receipt); err != nil {
		return group, err
	}
	for _, participant := range receipt.Participants {
		result, err := c.Export(ctx, participant.RunID)
		if err != nil {
			return group, err
		}
		group.Results = append(group.Results, result)
	}
	return group, nil
}

// CancelExperiment requests cancellation for all known runs. An acknowledgement
// is not proof that execution stopped; inspect their existing result endpoints.
func (c *Client) CancelExperiment(ctx context.Context, receipt ExperimentSubmission) error {
	if err := c.checkExperimentReceipt(ctx, receipt); err != nil {
		return err
	}
	var failures []error
	for _, participant := range receipt.Participants {
		if participant.RunID == "" {
			continue
		}
		if err := c.Cancel(ctx, participant.RunID, participant.ExecutorID); err != nil {
			failures = append(failures, fmt.Errorf("participant %d: %w", participant.OrderID, err))
		}
	}
	return errors.Join(failures...)
}

// Check every known run before returning grouped output or cancelling any run.
// Missing IDs remain unknown after uncertain submission and cannot be acted on.
func (c *Client) checkExperimentReceipt(ctx context.Context, receipt ExperimentSubmission) error {
	for _, participant := range receipt.Participants {
		if participant.RunID == "" {
			continue
		}
		detail, err := c.RunDetail(ctx, participant.RunID)
		if err != nil {
			return err
		}
		if receipt.ExperimentID == "" || detail.BatchID != receipt.ExperimentID || detail.OrderID != participant.OrderID || detail.ExecutorID != participant.ExecutorID || detail.Provenance != nil && detail.Provenance.WorkloadSHA256 != participant.SHA256 {
			return errors.New("client: experiment receipt disagrees with admitted membership")
		}
	}
	return nil
}
