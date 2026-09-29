// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package tesla

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
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
		Seed:            fixedSeed,
		ChainLength:     100, // small chain for fast tests
		EpochLength:     delay,
		DisclosureDelay: MinDisclosureDelay,
		Epoch:           epoch,
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
	payload := testIPv4([]byte("test packet payload"))

	ak, err := DeriveAK(k, testMeasurementID)
	if err != nil {
		t.Fatalf("DeriveAK: %v", err)
	}
	tag, err := PacketTag(ak, payload)
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
	ok, err = VerifyTag(k, epoch, testMeasurementID, testIPv4([]byte("tampered payload")), tag)
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

// TestDisclosedKey ensures the correct epoch is returned with d = 2.
func TestDisclosedKey(t *testing.T) {
	delay := time.Second
	ks := newTestSchedule(t, delay)
	anchor := ks.cfg.Epoch

	// In epochs 0 and 1 no key is disclosable yet.
	for _, at := range []time.Time{anchor, anchor.Add(delay), anchor.Add(2*delay - time.Nanosecond)} {
		if _, _, ok := ks.DisclosedKey(at); ok {
			t.Errorf("expected no disclosable key at %s", at.Sub(anchor))
		}
	}

	// At epoch 2 the key for epoch 0 is disclosable.
	idx, key, ok := ks.DisclosedKey(anchor.Add(2 * delay))
	if !ok || idx != 0 || !bytes.Equal(key, ks.keyForEpoch(0)) {
		t.Errorf("DisclosedKey(epoch 2) = %d, %x, %v; want 0, k_0", idx, key, ok)
	}

	// At epoch 5 the key for epoch 3 is disclosable.
	idx, key, ok = ks.DisclosedKey(anchor.Add(5 * delay))
	if !ok || idx != 3 || !bytes.Equal(key, ks.keyForEpoch(3)) {
		t.Errorf("DisclosedKey(epoch 5) = %d, %x, %v; want 3, k_3", idx, key, ok)
	}
}

// TestDisclosureDelayDefaultsAndBounds checks the derived default, which
// covers DefaultDisclosureWindow, and that a delay below two epochs is
// refused.
func TestDisclosureDelayDefaultsAndBounds(t *testing.T) {
	for _, tc := range []struct {
		epoch time.Duration
		want  int64
	}{
		{0, 90},
		{10 * time.Second, 90},
		{time.Second, 900},
		{7 * time.Second, 129},
		{30 * time.Second, 30},
		{10 * time.Minute, MinDisclosureDelay},
		{time.Hour, MinDisclosureDelay},
	} {
		if got := DefaultDisclosureDelay(tc.epoch); got != tc.want {
			t.Errorf("DefaultDisclosureDelay(%s) = %d; want %d", tc.epoch, got, tc.want)
		}
	}
	ks, err := NewKeySchedule(Config{Seed: fixedSeed, ChainLength: 8})
	if err != nil {
		t.Fatal(err)
	}
	if cfg := ks.Config(); cfg.EpochLength != DefaultEpochLength || cfg.DisclosureDelay != 90 || ks.DisclosureDelay() != 90 {
		t.Errorf("defaults: epoch %s, d %d; want %s and 90", cfg.EpochLength, cfg.DisclosureDelay, DefaultEpochLength)
	}
	for _, d := range []int64{1, -1} {
		if _, err := NewKeySchedule(Config{Seed: fixedSeed, ChainLength: 8, DisclosureDelay: d}); err == nil || !strings.Contains(err.Error(), "at least 2 epochs") {
			t.Errorf("DisclosureDelay %d: err = %v; want a refusal naming the minimum", d, err)
		}
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
	payload := testIPv4([]byte("probe payload data"))
	ak5, err := DeriveAK(k5, testMeasurementID)
	if err != nil {
		t.Fatalf("DeriveAK: %v", err)
	}
	tag, err := PacketTag(ak5, payload)
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
