// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"bytes"
	"testing"
	"time"
)

// retiredFixture returns a chain as it signed (I = 1 s, L = 6, d = 2) and the
// same chain re-derived from its seed and recorded wall origin as a
// disclosure-only schedule.
func retiredFixture(t *testing.T) (signing, retired *KeySchedule) {
	t.Helper()
	origin := time.Date(2026, 10, 5, 12, 0, 0, 123456789, time.UTC)
	cfg := Config{Seed: []byte("retired chain fixture"), EpochLength: time.Second, DisclosureDelay: 2, ChainLength: 6, Epoch: origin}
	signing, err := NewKeySchedule(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DisclosureOnly = true
	if retired, err = NewKeySchedule(cfg); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signing.Anchor(), retired.Anchor()) {
		t.Fatal("the re-derived chain has another anchor")
	}
	return signing, retired
}

// A disclosure-only schedule never signs: no epoch yields a key, on the
// pure-Go path (CurrentKey) or the per-run derivation (ComputeTagForPacket,
// which reads it), where the same chain configured for signing does.
func TestDisclosureOnlyScheduleNeverSigns(t *testing.T) {
	signing, retired := retiredFixture(t)
	origin := retired.Config().Epoch
	packet := testIPv4([]byte("retired chain payload"))
	for epoch := int64(0); epoch <= 10; epoch++ {
		at := origin.Add(time.Duration(epoch)*time.Second + 500*time.Millisecond)
		if key := retired.CurrentKey(at); key != nil {
			t.Fatalf("epoch %d: disclosure-only schedule returned a signing key", epoch)
		}
		if _, err := retired.ComputeTagForPacket(at, []byte("run"), packet); err == nil {
			t.Fatalf("epoch %d: disclosure-only schedule tagged a packet", epoch)
		}
	}
	if signing.CurrentKey(origin.Add(1500*time.Millisecond)) == nil {
		t.Fatal("the signing configuration of the same chain has no key in epoch 1")
	}
}

// From its recorded wall origin, a disclosure-only schedule discloses k_i from
// the start of epoch i+d and stops at k_{L-1} from FinalDisclosure on, as the
// chain it re-derives would have, also when now carries a monotonic reading.
func TestDisclosureOnlyScheduleDisclosesFromRecordedOrigin(t *testing.T) {
	signing, retired := retiredFixture(t)
	origin := retired.Config().Epoch
	if _, _, ok := retired.DisclosedKey(origin.Add(2*time.Second - time.Nanosecond)); ok {
		t.Fatal("a key was disclosed before epoch d")
	}
	for at, want := range map[time.Duration]int64{2 * time.Second: 0, 3500 * time.Millisecond: 1, 6 * time.Second: 4, 7 * time.Second: 5, time.Hour: 5} {
		epoch, key, ok := retired.DisclosedKey(origin.Add(at))
		signed, _ := signing.KeyAtEpoch(want)
		if !ok || epoch != want || !bytes.Equal(key, signed) {
			t.Errorf("at origin+%v disclosed (%d, %v); want k_%d of the signing chain", at, epoch, ok, want)
		}
	}
	if final := retired.FinalDisclosure(); !final.Equal(origin.Add(7 * time.Second)) {
		t.Errorf("final disclosure %v; want origin+7s", final)
	}

	// A recorded origin has no monotonic reading, so elapsed time is wall time.
	recorded := time.Now().Add(-3500 * time.Millisecond).Round(0)
	live, err := NewKeySchedule(Config{Seed: []byte("retired chain fixture"), EpochLength: time.Second, DisclosureDelay: 2, ChainLength: 6, Epoch: recorded, DisclosureOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if epoch, _, ok := live.DisclosedKey(time.Now()); !ok || epoch != 1 {
		t.Fatalf("disclosed (%d, %v) 3.5 s after the recorded origin; want k_1", epoch, ok)
	}
}

// A disclosure-only schedule is only ever a re-derived chain: without its
// recorded seed or origin it is refused rather than made random or fresh.
func TestDisclosureOnlyScheduleNeedsRecordedChain(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no seed":   {EpochLength: time.Second, ChainLength: 6, Epoch: time.Now(), DisclosureOnly: true},
		"no origin": {Seed: []byte("seed"), EpochLength: time.Second, ChainLength: 6, DisclosureOnly: true},
	} {
		if _, err := NewKeySchedule(cfg); err == nil {
			t.Errorf("%s: a disclosure-only schedule was created", name)
		}
	}
}
