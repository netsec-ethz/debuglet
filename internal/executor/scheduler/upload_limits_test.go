// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package scheduler

import (
	"errors"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
)

func TestStoredRunBytesCountsStoredEncodingAndModuleBoundary(t *testing.T) {
	spec := Spec{Wasm: make([]byte, MaxModuleBytes), Args: []string{"é", "", ","}, TransactionID: "世", Binding: controlsession.Binding{Incarnation: "one", SessionID: "two"}, Policy: Policy{Addresses: []string{"127.0.0.1"}}}
	size, err := StoredRunBytes(spec)
	// Arguments serialize to w6k=,,LA== (10 bytes); address to MTI3LjAuMC4x (12).
	want := int64(QueueRowCharge + MaxModuleBytes + 10 + 12 + 3 + 3 + 3)
	if err != nil || size != want {
		t.Fatalf("charge=%d want=%d err=%v", size, want, err)
	}
	spec.Wasm = append(spec.Wasm, 0)
	if _, err := StoredRunBytes(spec); !errors.Is(err, ErrUploadLimit) {
		t.Fatalf("one-over module limit=%v", err)
	}
}

func TestStoredRunBytesBoundsMetadataBeforeEncoding(t *testing.T) {
	spec := Spec{TransactionID: string(make([]byte, MaxStoredRunBytes-QueueRowCharge))}
	if charge, err := StoredRunBytes(spec); err != nil || charge != MaxStoredRunBytes {
		t.Fatalf("boundary=%d %v", charge, err)
	}
	spec.Args = []string{"a"}
	if _, err := StoredRunBytes(spec); !errors.Is(err, ErrUploadLimit) {
		t.Fatalf("oversized stored metadata=%v", err)
	}
}
