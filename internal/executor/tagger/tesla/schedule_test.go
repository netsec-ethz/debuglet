// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package tesla

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// measurementID used throughout tests — raw bytes of a fake UUID.
var testMeasurementID = []byte("test-measurement-id-001")

// fixedSeed gives deterministic results across runs.
// This is the secret tail k_L of the backward hash chain.
var fixedSeed = bytes.Repeat([]byte{0xAB}, 32)

func newTestSchedule(t *testing.T, delay time.Duration) *KeySchedule {
	t.Helper()
	epoch := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := NewKeySchedule(Config{
		Seed:        fixedSeed,
		ChainLength: 100, // small chain for fast tests
		Delay:       delay,
		Epoch:       epoch,
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	return ks
}

// TestBackwardChainDirection verifies the core invariant of the TESLA backward
// chain: k_i = H(k_{i+1}).
func TestBackwardChainDirection(t *testing.T) {
	ks := newTestSchedule(t, time.Second)

	// For each epoch i, hashing k_{i+1} once must yield k_i.
	h := sha256.New()
	for i := int64(0); i < 20; i++ {
		ki := ks.keyForEpoch(i)
		ki1 := ks.keyForEpoch(i + 1)

		h.Reset()
		h.Write(ki1)
		expected := h.Sum(nil)

		if !bytes.Equal(ki, expected) {
			t.Errorf("epoch %d: k_%d ≠ H(k_%d): backward chain direction violated", i, i, i+1)
		}
	}
}

// TestAnchorIsHashOfChain verifies that k_0 == H^L(k_L) (the seed).
func TestAnchorIsHashOfChain(t *testing.T) {
	ks := newTestSchedule(t, time.Second)
	L := ks.cfg.ChainLength

	// Hash the seed L times to reproduce k_0.
	key := make([]byte, len(fixedSeed))
	copy(key, fixedSeed)
	h := sha256.New()
	for i := int64(0); i < L; i++ {
		h.Reset()
		h.Write(key)
		key = h.Sum(nil)
	}

	if !bytes.Equal(key, ks.Anchor()) {
		t.Errorf("anchor mismatch: H^%d(seed) = %x, anchor = %x", L, key, ks.Anchor())
	}
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

// TestVerifyChain verifies the VerifyChain helper against the public anchor.
func TestVerifyChain(t *testing.T) {
	ks := newTestSchedule(t, time.Second)
	anchor := ks.Anchor()

	for _, epoch := range []int64{0, 1, 5, 10, 20} {
		k := ks.keyForEpoch(epoch)
		if !VerifyChain(anchor, k, epoch) {
			t.Errorf("VerifyChain failed for epoch %d", epoch)
		}
	}

	// A tampered key must fail.
	k := ks.keyForEpoch(5)
	tampered := make([]byte, len(k))
	copy(tampered, k)
	tampered[0] ^= 0xFF
	if VerifyChain(anchor, tampered, 5) {
		t.Error("VerifyChain passed for a tampered key")
	}
}

// TestDeriveFromDisclosed verifies that a verifier can reconstruct an earlier
// epoch key from a later disclosed key by hashing forward (backward-chain
// semantics: disclosed key is at a higher epoch index).
func TestDeriveFromDisclosed(t *testing.T) {
	ks := newTestSchedule(t, time.Second)

	// Executor discloses k_5 (epoch 5).
	disclosed := ks.keyForEpoch(5)

	// Reconstruct k_5 from k_5 (trivial).
	derived, err := DeriveFromDisclosed(disclosed, 5, 5)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed(5→5): %v", err)
	}
	if !bytes.Equal(derived, ks.keyForEpoch(5)) {
		t.Errorf("DeriveFromDisclosed(5→5): got %x, want %x", derived, ks.keyForEpoch(5))
	}

	// Reconstruct k_3 from k_5 (hash k_5 forward 2 steps: k_3 = H^2(k_5)).
	derived3, err := DeriveFromDisclosed(disclosed, 5, 3)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed(5→3): %v", err)
	}
	if !bytes.Equal(derived3, ks.keyForEpoch(3)) {
		t.Errorf("DeriveFromDisclosed(5→3): got %x, want %x", derived3, ks.keyForEpoch(3))
	}

	// Reconstruct k_0 from k_5 (hash forward 5 steps).
	derived0, err := DeriveFromDisclosed(disclosed, 5, 0)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed(5→0): %v", err)
	}
	if !bytes.Equal(derived0, ks.keyForEpoch(0)) {
		t.Errorf("DeriveFromDisclosed(5→0): got %x, want %x", derived0, ks.keyForEpoch(0))
	}
}

// TestDeriveFromDisclosedError ensures attempting to derive a later epoch from
// an earlier disclosed key returns an error (forbidden in backward chain).
func TestDeriveFromDisclosedError(t *testing.T) {
	ks := newTestSchedule(t, time.Second)
	disclosed := ks.keyForEpoch(3)
	_, err := DeriveFromDisclosed(disclosed, 3, 5)
	if err == nil {
		t.Error("expected error when deriving later epoch from earlier disclosed key, got nil")
	}
}

// TestDeriveFromDisclosedMatchesVerifyChain checks that a reconstructed key
// also passes VerifyChain, providing end-to-end verification semantics.
func TestDeriveFromDisclosedMatchesVerifyChain(t *testing.T) {
	ks := newTestSchedule(t, time.Second)
	anchor := ks.Anchor()

	// Suppose epoch 10 is disclosed; reconstruct epoch 7.
	disclosed := ks.keyForEpoch(10)
	reconstructed, err := DeriveFromDisclosed(disclosed, 10, 7)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed: %v", err)
	}
	if !VerifyChain(anchor, reconstructed, 7) {
		t.Error("reconstructed key failed VerifyChain")
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

	k1 := ks.CurrentKey(epoch.Add(delay))
	k2 := ks.CurrentKey(epoch.Add(2 * delay))
	if k1 == nil || k2 == nil {
		t.Fatalf("CurrentKey in epochs 1 and 2 = %x, %x; want usable keys", k1, k2)
	}
	if bytes.Equal(k1, k2) {
		t.Error("CurrentKey did not change after one delay period")
	}
}

// TestDisclosedKey ensures the correct epoch is returned.
func TestDisclosedKey(t *testing.T) {
	delay := time.Second
	ks := newTestSchedule(t, delay)
	anchor := ks.cfg.Epoch

	// At start (epoch 0), no key is disclosable yet.
	_, _, ok := ks.DisclosedKey(anchor)
	if ok {
		t.Error("expected no disclosable key at epoch 0")
	}

	// At epoch 1 (anchor + 1*delay), the key for epoch 0 should be disclosable.
	idx, key, ok := ks.DisclosedKey(anchor.Add(delay))
	if !ok {
		t.Error("expected disclosable key (epoch 0) at epoch 1")
	}
	if idx != 0 {
		t.Errorf("expected disclosable epoch 0, got %d", idx)
	}
	expected0 := ks.keyForEpoch(0)
	if !bytes.Equal(key, expected0) {
		t.Errorf("disclosed key mismatch: got %x, want %x", key, expected0)
	}

	// At epoch 3 (anchor + 3*delay), the key for epoch 2 should be disclosable.
	idx, key, ok = ks.DisclosedKey(anchor.Add(3 * delay))
	if !ok {
		t.Error("expected disclosable key at epoch 3")
	}
	if idx != 2 {
		t.Errorf("expected disclosable epoch 2, got %d", idx)
	}
	expected2 := ks.keyForEpoch(2)
	if !bytes.Equal(key, expected2) {
		t.Errorf("disclosed key mismatch: got %x, want %x", key, expected2)
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

// TestFullVerificationFlow simulates the complete TESLA verification workflow:
// executor tags a probe, discloses the key later, verifier reconstructs and checks.
func TestFullVerificationFlow(t *testing.T) {
	ks := newTestSchedule(t, time.Second)
	anchor := ks.Anchor()

	// Executor tags a probe at epoch 5.
	probeEpoch := int64(5)
	k5 := ks.keyForEpoch(probeEpoch)
	payload := []byte("probe payload data")
	ak5, err := DeriveAK(k5, testMeasurementID)
	if err != nil {
		t.Fatalf("DeriveAK: %v", err)
	}
	tag, err := ComputeTag(ak5, payload)
	if err != nil {
		t.Fatalf("ComputeTag: %v", err)
	}

	// After disclosure delay, executor reveals k_10 (τ = 10).
	disclosedEpoch := int64(10)
	disclosedKey := ks.keyForEpoch(disclosedEpoch)

	// Verifier reconstructs k_5 from k_10: k_5 = H^(10-5)(k_10).
	reconstructed, err := DeriveFromDisclosed(disclosedKey, disclosedEpoch, probeEpoch)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed: %v", err)
	}

	// Verifier confirms consistency: H^5(k_5) == k_0.
	if !VerifyChain(anchor, reconstructed, probeEpoch) {
		t.Fatal("VerifyChain failed for reconstructed key")
	}

	// Verifier derives ak and checks the tag.
	ok, err := VerifyTag(reconstructed, probeEpoch, testMeasurementID, payload, tag)
	if err != nil {
		t.Fatalf("VerifyTag: %v", err)
	}
	if !ok {
		t.Error("full verification flow failed: tag mismatch")
	}
}
