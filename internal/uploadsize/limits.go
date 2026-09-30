// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package uploadsize defines the same payload bounds for HTTP admission and
// direct executor uploads. Transport envelopes have their own encoded limits.
package uploadsize

import (
	"errors"
	"fmt"
)

const (
	MaxModuleBytes    = 24 << 20
	MaxStoredRunBytes = 32 << 20
	MaxBatchRuns      = 128
	RowCharge         = 512
)

var ErrLimit = errors.New("upload size limit reached")

// StoredBytes counts decoded WASM, base64/comma encoded argument/address
// columns, control/transaction text and fixed row metadata, without making a
// serialized payload copy. The executor's persisted queue uses this charge.
func StoredBytes(wasm []byte, args, addresses []string, textFields ...string) (int64, error) {
	return StoredBytesForModule(int64(len(wasm)), args, addresses, textFields...)
}

// StoredBytesForModule also serves the HTTP intent boundary before allocating
// decoded WASM. Its caller must supply an upper bound on the decoded length.
func StoredBytesForModule(moduleBytes int64, args, addresses []string, textFields ...string) (int64, error) {
	if moduleBytes < 0 || moduleBytes > MaxModuleBytes {
		return 0, fmt.Errorf("%w: decoded WASM exceeds %d bytes", ErrLimit, MaxModuleBytes)
	}
	total := int64(RowCharge) + moduleBytes
	add := func(size int64) bool {
		if size > MaxStoredRunBytes-total {
			return false
		}
		total += size
		return true
	}
	for _, text := range textFields {
		if !add(int64(len(text))) {
			return 0, ErrLimit
		}
	}
	for _, list := range [][]string{args, addresses} {
		for i, value := range list {
			if len(value) > MaxStoredRunBytes || !add((int64(len(value))+2)/3*4) {
				return 0, ErrLimit
			}
			if i > 0 && !add(1) {
				return 0, ErrLimit
			}
		}
	}
	return total, nil
}
