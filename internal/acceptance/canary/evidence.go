package main

import (
	"encoding/json"
	"errors"
)

const receiptSizeLimit = 4 << 20

// WriteEvidence preserves unavailable observations as null. It never fills in
// success claims: Run supplies the final observations after joining cleanup.
// The directory must already exist and remain exclusively owned by the caller.
func WriteEvidence(dir string, evidence Evidence) error {
	data, err := json.Marshal(evidence)
	if err != nil || len(data) >= receiptSizeLimit {
		return errors.New("cannot encode bounded local evidence")
	}
	return publishEvidence(dir, append(data, '\n'))
}

// DecodeReceipt checks structure only. The driver separately verifies the
// executor, UUIDs and state before treating any receipt as an observation.
func DecodeReceipt(data []byte) (RunReceipt, error) {
	invalid := errors.New("invalid installed run receipt")
	if len(data) > receiptSizeLimit {
		return RunReceipt{}, invalid
	}
	if _, err := strictFields(data, []string{"executor_id", "state"}, []string{"id", "transaction_id", "error"}, nil); err != nil {
		return RunReceipt{}, invalid
	}
	var receipt RunReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return RunReceipt{}, invalid
	}
	return receipt, nil
}
