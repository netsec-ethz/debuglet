// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"bytes"
	"testing"
	"time"
)

// TestNoSigningKeyBeforeEpochOne checks the availability rule: k_0 is the
// public anchor, so epoch 0 and any instant before Epoch have no signing key,
// and k_1 signs from the start of epoch 1.
func TestNoSigningKeyBeforeEpochOne(t *testing.T) {
	delay := time.Second
	ks := newTestSchedule(t, delay)
	start := ks.Config().Epoch
	anchor := ks.Anchor()
	payload := []byte("first epoch payload")

	for _, at := range []time.Time{start.Add(-time.Nanosecond), start, start.Add(delay - time.Nanosecond)} {
		if k := ks.CurrentKey(at); k != nil {
			if bytes.Equal(k, anchor) {
				t.Errorf("CurrentKey(%s) equals Anchor(); want nil", at.Sub(start))
			} else {
				t.Errorf("CurrentKey(%s) = %x; want nil", at.Sub(start), k)
			}
		}
		if _, err := ks.ComputeTagForPacket(at, testMeasurementID, payload); err == nil {
			t.Errorf("ComputeTagForPacket(%s) succeeded without a usable key", at.Sub(start))
		}
		if _, err := ks.ComputeBPFTagForPacket(at, testMeasurementID, payload); err == nil {
			t.Errorf("ComputeBPFTagForPacket(%s) succeeded without a usable key", at.Sub(start))
		}
	}

	k1 := ks.CurrentKey(start.Add(delay))
	want1, err := ks.KeyAtEpoch(1)
	if err != nil {
		t.Fatalf("KeyAtEpoch(1): %v", err)
	}
	if k1 == nil || bytes.Equal(k1, anchor) || !bytes.Equal(k1, want1) {
		t.Fatalf("CurrentKey(Epoch+Delay) = %x; want k_1 %x (anchor %x)", k1, want1, anchor)
	}
	if !VerifyChain(anchor, k1, 1) {
		t.Error("VerifyChain(anchor, k_1, 1) = false")
	}
	want2, _ := ks.KeyAtEpoch(2)
	if k2 := ks.CurrentKey(start.Add(2 * delay)); !bytes.Equal(k2, want2) || bytes.Equal(k2, k1) {
		t.Errorf("CurrentKey(Epoch+2*Delay) = %x; want k_2 %x", k2, want2)
	}
}

// TestAnchorCannotProduceAcceptedTag checks that the public anchor cannot
// generate a tag the executor emits or a verifier accepts for the first
// signing epoch.
func TestAnchorCannotProduceAcceptedTag(t *testing.T) {
	delay := time.Second
	ks := newTestSchedule(t, delay)
	start := ks.Config().Epoch
	payload := []byte("anchor forgery payload")

	forgedAK, err := DeriveAK(ks.Anchor(), testMeasurementID)
	if err != nil {
		t.Fatalf("DeriveAK(anchor): %v", err)
	}
	forged, _ := ComputeTag(forgedAK, payload)
	forgedBPF, _ := ComputeBPFTag(forgedAK, payload)

	if tag, err := ks.ComputeTagForPacket(start, testMeasurementID, payload); err == nil && tag == forged {
		t.Error("the tag emitted in epoch 0 is computable from the public anchor")
	}
	if tag, err := ks.ComputeBPFTagForPacket(start, testMeasurementID, payload); err == nil && tag == forgedBPF {
		t.Error("the BPF tag emitted in epoch 0 is computable from the public anchor")
	}

	k1, _ := ks.KeyAtEpoch(1)
	if ok, err := VerifyTag(k1, 1, testMeasurementID, payload, forged); err != nil || ok {
		t.Errorf("VerifyTag(k_1, anchor-derived tag) = %v, %v; want false", ok, err)
	}
	if ok, err := VerifyBPFTag(k1, 1, testMeasurementID, payload, forgedBPF); err != nil || ok {
		t.Errorf("VerifyBPFTag(k_1, anchor-derived tag) = %v, %v; want false", ok, err)
	}

	real, err := ks.ComputeTagForPacket(start.Add(delay), testMeasurementID, payload)
	if err != nil {
		t.Fatalf("ComputeTagForPacket(epoch 1): %v", err)
	}
	if ok, err := VerifyTag(k1, 1, testMeasurementID, payload, real); err != nil || !ok {
		t.Errorf("VerifyTag(k_1, epoch-1 tag) = %v, %v; want true", ok, err)
	}
	realBPF, err := ks.ComputeBPFTagForPacket(start.Add(delay), testMeasurementID, payload)
	if err != nil {
		t.Fatalf("ComputeBPFTagForPacket(epoch 1): %v", err)
	}
	if ok, err := VerifyBPFTag(k1, 1, testMeasurementID, payload, realBPF); err != nil || !ok {
		t.Errorf("VerifyBPFTag(k_1, epoch-1 tag) = %v, %v; want true", ok, err)
	}
}

// TestFirstSigningKeyDisclosedAfterItsEpoch checks that the disclosure
// boundary is unchanged: k_1 is disclosed only once epoch 1 has ended.
func TestFirstSigningKeyDisclosedAfterItsEpoch(t *testing.T) {
	delay := time.Second
	ks := newTestSchedule(t, delay)
	start := ks.Config().Epoch
	k0, _ := ks.KeyAtEpoch(0)
	k1, _ := ks.KeyAtEpoch(1)

	if idx, key, ok := ks.DisclosedKey(start.Add(delay)); !ok || idx != 0 || !bytes.Equal(key, k0) {
		t.Errorf("DisclosedKey(epoch 1) = %d, %x, %v; want 0, k_0", idx, key, ok)
	}
	if idx, key, ok := ks.DisclosedKey(start.Add(2*delay - time.Nanosecond)); !ok || idx != 0 || !bytes.Equal(key, k0) {
		t.Errorf("DisclosedKey(end of epoch 1) = %d, %x, %v; want 0, k_0", idx, key, ok)
	}
	if idx, key, ok := ks.DisclosedKey(start.Add(2 * delay)); !ok || idx != 1 || !bytes.Equal(key, k1) {
		t.Errorf("DisclosedKey(epoch 2) = %d, %x, %v; want 1, k_1", idx, key, ok)
	}
}

// TestDelayedStartHasUsableKey checks that a schedule whose Epoch lies in the
// past signs immediately.
func TestDelayedStartHasUsableKey(t *testing.T) {
	ks, err := NewKeySchedule(Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	now := time.Now()
	k := ks.CurrentKey(now)
	if k == nil || bytes.Equal(k, ks.Anchor()) {
		t.Fatalf("CurrentKey one hour after Epoch = %x; want a non-anchor key", k)
	}
	if _, err := ks.ComputeTagForPacket(now, testMeasurementID, []byte("late start")); err != nil {
		t.Errorf("ComputeTagForPacket one hour after Epoch: %v", err)
	}
}
