// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"bytes"
	"testing"
	"time"
)

// TestExhaustedChainHasNoSigningKey checks the end of the chain: k_L is never
// disclosed, so epoch L and every later instant have no signing key, while
// k_{L-1} is still disclosed, d epochs after its own, and verifies against
// the anchor.
func TestExhaustedChainHasNoSigningKey(t *testing.T) {
	delay := time.Second
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := NewKeySchedule(Config{Seed: fixedSeed, ChainLength: 3, EpochLength: delay, DisclosureDelay: 2, Epoch: start})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	at := func(epoch int64) time.Time { return start.Add(time.Duration(epoch) * delay) }
	payload := []byte("exhausted chain payload")
	k2, _ := ks.KeyAtEpoch(2)

	if k := ks.CurrentKey(at(2)); !bytes.Equal(k, k2) {
		t.Fatalf("CurrentKey(epoch 2) = %x; want k_2 %x", k, k2)
	}
	if ks.Exhausted(at(3).Add(-time.Nanosecond)) {
		t.Error("Exhausted before epoch 3")
	}
	if !ks.Expiry().Equal(at(3)) {
		t.Errorf("Expiry() = %s; want the start of epoch 3", ks.Expiry())
	}
	for _, epoch := range []int64{3, 100} {
		if k := ks.CurrentKey(at(epoch)); k != nil {
			t.Errorf("CurrentKey(epoch %d) = %x; want nil", epoch, k)
		}
		if !ks.Exhausted(at(epoch)) {
			t.Errorf("Exhausted(epoch %d) = false", epoch)
		}
		if _, err := ks.ComputeTagForPacket(at(epoch), testMeasurementID, payload); err == nil {
			t.Errorf("ComputeTagForPacket(epoch %d) succeeded on an exhausted chain", epoch)
		}
	}
	// k_2 is due at the start of epoch 2+d = 4, after Expiry, and stays the
	// disclosed key from then on.
	if idx, _, ok := ks.DisclosedKey(at(3)); !ok || idx != 1 {
		t.Errorf("DisclosedKey(epoch 3) = (%d, %v); want (1, true)", idx, ok)
	}
	for _, epoch := range []int64{4, 100} {
		idx, key, ok := ks.DisclosedKey(at(epoch))
		if !ok || idx != 2 || !bytes.Equal(key, k2) {
			t.Errorf("DisclosedKey(epoch %d) = (%d, %x, %v); want (2, k_2, true)", epoch, idx, key, ok)
		}
	}
	if !VerifyChain(ks.Anchor(), k2, 2) {
		t.Error("VerifyChain(anchor, k_2, 2) = false")
	}
}
