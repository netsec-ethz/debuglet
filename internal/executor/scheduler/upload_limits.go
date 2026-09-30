// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package scheduler

import (
	"errors"
	"fmt"
)

const (
	// MaxModuleBytes is a decoded WASM limit. HTTP's separate 32 MiB envelope
	// includes base64 and JSON overhead; gRPC's message ceiling includes protobuf.
	MaxModuleBytes    = 24 << 20
	MaxStoredRunBytes = 32 << 20
	// QueueRowCharge accounts for fixed row metadata independently of payloads.
	QueueRowCharge = 512
)

var (
	ErrUploadLimit = errors.New("executor upload size limit reached")
	ErrQueueLimit  = errors.New("executor retained queue limit reached")
)

// QueueLimits bounds retained execution rows, including started and quarantined
// rows. Output spools have a separate budget. Limits are fixed on construction.
type QueueLimits struct {
	Bytes int64
	Runs  int64
}

func DefaultQueueLimits() QueueLimits { return QueueLimits{Bytes: 256 << 20, Runs: 1024} }

func (l QueueLimits) Validate() error {
	if l.Bytes < QueueRowCharge || l.Runs <= 0 {
		return errors.New("retained queue requires positive row and byte limits")
	}
	return nil
}

// StoredRunBytes counts the bytes the queue stores: decoded WASM, encoded list
// columns, text columns and a fixed per-row charge. It checks lengths before
// serializing argument/address lists, and does not allocate payload copies.
func StoredRunBytes(spec Spec) (int64, error) {
	if len(spec.Wasm) > MaxModuleBytes {
		return 0, fmt.Errorf("%w: decoded WASM exceeds %d bytes", ErrUploadLimit, MaxModuleBytes)
	}
	total := int64(QueueRowCharge) + int64(len(spec.Wasm))
	add := func(size int64) bool {
		if size > MaxStoredRunBytes-total {
			return false
		}
		total += size
		return true
	}
	for _, value := range []string{spec.TransactionID, spec.Binding.Incarnation, spec.Binding.SessionID} {
		if !add(int64(len(value))) {
			return 0, ErrUploadLimit
		}
	}
	for _, list := range [][]string{spec.Args, spec.Policy.Addresses} {
		for i, value := range list {
			// Base64 is stored with comma separators by database.CommaSeparatedList.
			if len(value) > MaxStoredRunBytes || !add((int64(len(value))+2)/3*4) {
				return 0, ErrUploadLimit
			}
			if i > 0 && !add(1) {
				return 0, ErrUploadLimit
			}
		}
	}
	return total, nil
}
