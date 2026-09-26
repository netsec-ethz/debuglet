// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// TestMapEntryEmptyBeforeEpochOne checks the BPF map decision: nothing is
// installed while only the public anchor would apply, and the entry derived
// from k_t is installed from epoch 1 on.
func TestMapEntryEmptyBeforeEpochOne(t *testing.T) {
	delay := 10 * time.Second
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:        bytes.Repeat([]byte{0x5A}, 32),
		ChainLength: 16,
		Delay:       delay,
		Epoch:       start,
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	measurement := []byte("measurement-first-epoch")

	for _, at := range []time.Time{start.Add(-time.Second), start, start.Add(delay - time.Nanosecond)} {
		entry, install, err := akEntryAt(ks, measurement, at)
		if err != nil || install {
			t.Errorf("akEntryAt(%s) = %+v, %v, %v; want no entry", at.Sub(start), entry, install, err)
		}
	}

	for epoch := int64(1); epoch <= 3; epoch++ {
		at := start.Add(time.Duration(epoch) * delay)
		entry, install, err := akEntryAt(ks, measurement, at)
		if err != nil || !install {
			t.Fatalf("akEntryAt(epoch %d) = %v, %v; want an entry", epoch, install, err)
		}
		k, _ := ks.KeyAtEpoch(epoch)
		ak, err := tesla.DeriveAK(k, measurement)
		if err != nil {
			t.Fatalf("DeriveAK: %v", err)
		}
		if want := akFromKey(ak); entry != want {
			t.Errorf("akEntryAt(epoch %d) = %+v; want %+v", epoch, entry, want)
		}
	}
}
