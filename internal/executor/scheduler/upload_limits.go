// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package scheduler

import (
	"errors"
	"github.com/netsec-ethz/debuglet/internal/uploadsize"
)

const (
	// MaxModuleBytes is a decoded WASM limit. HTTP's separate 32 MiB envelope
	// includes base64 and JSON overhead; gRPC's message ceiling includes protobuf.
	MaxModuleBytes    = uploadsize.MaxModuleBytes
	MaxStoredRunBytes = uploadsize.MaxStoredRunBytes
	// QueueRowCharge accounts for fixed row metadata independently of payloads.
	QueueRowCharge = uploadsize.RowCharge
)

var (
	ErrUploadLimit = uploadsize.ErrLimit
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
	return uploadsize.StoredBytes(spec.Wasm, spec.Args, spec.Policy.Addresses,
		spec.TransactionID, spec.Binding.Incarnation, spec.Binding.SessionID)
}
