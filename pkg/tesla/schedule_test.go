// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tesla

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// measurementID used throughout tests — raw bytes of a fake UUID.
var testMeasurementID = []byte("test-measurement-id-001")

// fixedSeed gives deterministic results across runs.
var fixedSeed = bytes.Repeat([]byte{0xAB}, 32)

func newTestSchedule(t *testing.T, delay time.Duration) *KeySchedule {
	t.Helper()
	epoch := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := NewKeySchedule(Config{
		Seed:  fixedSeed,
		Delay: delay,
		Epoch: epoch,
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	return ks
}

// TestKeyChainDeterminism ensures the same seed always produces the same chain.
func TestKeyChainDeterminism(t *testing.T) {
	ks1 := newTestSchedule(t, time.Second)
	ks2 := newTestSchedule(t, time.Second)

	for epoch := int64(0); epoch < 20; epoch++ {
		k1 := ks1.keyForEpoch(epoch)
		k2 := ks2.keyForEpoch(epoch)
		if !bytes.Equal(k1, k2) {
			t.Errorf("epoch %d: key mismatch between two identical schedules", epoch)
		}
	}
}

// TestKeyChainUniqueness ensures consecutive keys differ.
func TestKeyChainUniqueness(t *testing.T) {
	ks := newTestSchedule(t, time.Second)
	prev := ks.keyForEpoch(0)
	for epoch := int64(1); epoch < 20; epoch++ {
		cur := ks.keyForEpoch(epoch)
		if bytes.Equal(prev, cur) {
			t.Errorf("epoch %d and %d have the same key", epoch-1, epoch)
		}
		prev = cur
	}
}

// TestDeriveFromDisclosed verifies that a verifier can reconstruct a target
// epoch key from a later disclosed key by hashing forward.
func TestDeriveFromDisclosed(t *testing.T) {
	ks := newTestSchedule(t, time.Second)

	// Compute expected key at epoch 3 directly.
	expected := ks.keyForEpoch(3)

	// Simulate disclosure: executor discloses key at epoch 3.
	disclosed := ks.keyForEpoch(3)

	// Derive epoch 3 from epoch 3 (trivial: should be equal).
	derived, err := DeriveFromDisclosed(disclosed, 3, 3)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed(3→3): %v", err)
	}
	if !bytes.Equal(derived, expected) {
		t.Errorf("DeriveFromDisclosed(3→3): got %x, want %x", derived, expected)
	}

	// Derive epoch 5 from epoch 3 (forward 2 hashes).
	expected5 := ks.keyForEpoch(5)
	derived5, err := DeriveFromDisclosed(disclosed, 3, 5)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed(3→5): %v", err)
	}
	if !bytes.Equal(derived5, expected5) {
		t.Errorf("DeriveFromDisclosed(3→5): got %x, want %x", derived5, expected5)
	}
}

// TestDeriveFromDisclosedError ensures attempting to go backwards returns an error.
func TestDeriveFromDisclosedError(t *testing.T) {
	ks := newTestSchedule(t, time.Second)
	disclosed := ks.keyForEpoch(5)
	_, err := DeriveFromDisclosed(disclosed, 5, 3)
	if err == nil {
		t.Error("expected error when deriving earlier epoch from later key, got nil")
	}
}

// TestDeriveAKDeterminism ensures DeriveAK is deterministic.
func TestDeriveAKDeterminism(t *testing.T) {
	k := bytes.Repeat([]byte{0x01}, 32)
	ak1, err := DeriveAK(k, testMeasurementID)
	if err != nil {
		t.Fatalf("DeriveAK: %v", err)
	}
	ak2, err := DeriveAK(k, testMeasurementID)
	if err != nil {
		t.Fatalf("DeriveAK: %v", err)
	}
	if !bytes.Equal(ak1, ak2) {
		t.Error("DeriveAK is not deterministic")
	}
}

// TestDeriveAKUniqueness ensures different measurement IDs produce different ak values.
func TestDeriveAKUniqueness(t *testing.T) {
	k := bytes.Repeat([]byte{0x01}, 32)
	ak1, _ := DeriveAK(k, []byte("measurement-A"))
	ak2, _ := DeriveAK(k, []byte("measurement-B"))
	if bytes.Equal(ak1, ak2) {
		t.Error("DeriveAK produced same key for different measurement IDs")
	}
}

// TestComputeTagDeterminism ensures the same inputs produce the same 16-bit tag.
func TestComputeTagDeterminism(t *testing.T) {
	ak := bytes.Repeat([]byte{0x02}, 32)
	payload := []byte("hello debuglet packet")

	tag1, err := ComputeTag(ak, payload)
	if err != nil {
		t.Fatalf("ComputeTag: %v", err)
	}
	tag2, err := ComputeTag(ak, payload)
	if err != nil {
		t.Fatalf("ComputeTag: %v", err)
	}
	if tag1 != tag2 {
		t.Errorf("ComputeTag not deterministic: %04x vs %04x", tag1, tag2)
	}
}

// TestComputeTagSensitivity ensures a 1-byte change in payload changes the tag.
func TestComputeTagSensitivity(t *testing.T) {
	ak := bytes.Repeat([]byte{0x03}, 32)
	payload1 := []byte("hello debuglet")
	payload2 := []byte("Hello debuglet") // capital H
	tag1, _ := ComputeTag(ak, payload1)
	tag2, _ := ComputeTag(ak, payload2)
	if tag1 == tag2 {
		t.Error("tag did not change when payload changed (collision or broken HMAC)")
	}
}

// TestVerifyTag round-trips tag computation and verification.
func TestVerifyTag(t *testing.T) {
	ks := newTestSchedule(t, time.Second)
	epoch := int64(7)
	k := ks.keyForEpoch(epoch)
	payload := []byte("test packet payload")

	ak, err := DeriveAK(k, testMeasurementID)
	if err != nil {
		t.Fatalf("DeriveAK: %v", err)
	}
	tag, err := ComputeTag(ak, payload)
	if err != nil {
		t.Fatalf("ComputeTag: %v", err)
	}

	ok, err := VerifyTag(k, epoch, testMeasurementID, payload, tag)
	if err != nil {
		t.Fatalf("VerifyTag: %v", err)
	}
	if !ok {
		t.Error("VerifyTag returned false for a valid tag")
	}

	// Tampered payload must fail.
	ok, err = VerifyTag(k, epoch, testMeasurementID, []byte("tampered payload"), tag)
	if err != nil {
		t.Fatalf("VerifyTag (tampered): %v", err)
	}
	if ok {
		t.Error("VerifyTag returned true for a tampered payload")
	}
}

// TestCurrentKeyAdvances ensures the current key changes as time advances.
func TestCurrentKeyAdvances(t *testing.T) {
	delay := 100 * time.Millisecond
	ks := newTestSchedule(t, delay)
	epoch := ks.cfg.Epoch

	k0 := ks.CurrentKey(epoch)
	k1 := ks.CurrentKey(epoch.Add(delay))
	if bytes.Equal(k0, k1) {
		t.Error("CurrentKey did not change after one delay period")
	}
}

// TestDisclosedKey ensures the correct epoch is returned.
func TestDisclosedKey(t *testing.T) {
	delay := time.Second
	ks := newTestSchedule(t, delay)
	epoch := ks.cfg.Epoch

	// At epoch 0 there is no disclosable key.
	_, _, ok := ks.DisclosedKey(epoch)
	if ok {
		t.Error("expected no disclosable key at epoch 0")
	}

	// At epoch 2 the key for epoch 1 should be disclosable.
	_, idx, key, ok2 := ks.cfg.Epoch, int64(0), []byte(nil), false
	idx, key, ok2 = ks.DisclosedKey(epoch.Add(2 * delay))
	if !ok2 {
		t.Error("expected disclosable key at epoch 2")
	}
	if idx != 1 {
		t.Errorf("expected disclosable epoch 1, got %d", idx)
	}
	expected := ks.keyForEpoch(1)
	if !bytes.Equal(key, expected) {
		t.Errorf("disclosed key mismatch: got %x, want %x", key, expected)
	}
}

// TestTagFitsIn16Bits ensures tag is always a valid 16-bit value.
func TestTagFitsIn16Bits(t *testing.T) {
	ak := bytes.Repeat([]byte{0xFF}, 32)
	for i := 0; i < 100; i++ {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, uint32(i))
		tag, err := ComputeTag(ak, payload)
		if err != nil {
			t.Fatalf("ComputeTag[%d]: %v", i, err)
		}
		// tag is uint16 — no need to check range, Go's type system guarantees it.
		_ = tag
	}
}
