// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// fakeHolder is an installed key whose epoch the test moves by hand.
type fakeHolder struct {
	mu        sync.Mutex
	epoch     int64
	installed bool
}

func (h *fakeHolder) InstalledEpoch() (int64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.epoch, h.installed
}

func (h *fakeHolder) hold(epoch int64) {
	h.mu.Lock()
	h.epoch, h.installed = epoch, true
	h.mu.Unlock()
}

func (h *fakeHolder) release() {
	h.mu.Lock()
	h.installed = false
	h.mu.Unlock()
}

func disclosureSchedule(t *testing.T, length int64) (*KeySchedule, func(epoch int64) time.Time) {
	t.Helper()
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	const delay = 10 * time.Second
	ks, err := NewKeySchedule(Config{Seed: bytes.Repeat([]byte{0x5A}, 32), ChainLength: length, Delay: delay, Epoch: start})
	if err != nil {
		t.Fatal(err)
	}
	return ks, func(epoch int64) time.Time { return start.Add(time.Duration(epoch) * delay) }
}

func wantDisclosed(t *testing.T, ks *KeySchedule, at time.Time, want int64) {
	t.Helper()
	idx, key, ok := ks.DisclosedKey(at)
	if !ok || idx != want {
		t.Fatalf("DisclosedKey = %d, %v; want %d", idx, ok, want)
	}
	if k, _ := ks.KeyAtEpoch(want); !bytes.Equal(key, k) {
		t.Fatalf("DisclosedKey returned a key other than k_%d", want)
	}
}

// TestDisclosureCappedByInstalledKeys crosses the boundary into epoch 5 with
// no, one and two holders: a holder still on epoch 4 caps disclosure at 3,
// and k_4 is disclosed on the same instant the last holder moves off it.
func TestDisclosureCappedByInstalledKeys(t *testing.T) {
	ks, at := disclosureSchedule(t, 16)
	boundary := at(5)

	wantDisclosed(t, ks, boundary, 4)

	a := &fakeHolder{}
	a.hold(4)
	ks.RegisterInstalled(a)
	wantDisclosed(t, ks, boundary.Add(-time.Nanosecond), 3)
	wantDisclosed(t, ks, boundary, 3)

	b := &fakeHolder{}
	b.hold(4)
	ks.RegisterInstalled(b)
	a.hold(5)
	wantDisclosed(t, ks, boundary, 3)
	b.hold(5)
	wantDisclosed(t, ks, boundary, 4)

	// A holder behind by several epochs caps at its own epoch, and a released
	// holder no longer caps anything.
	b.hold(2)
	wantDisclosed(t, ks, at(9), 1)
	b.release()
	wantDisclosed(t, ks, at(9), 4)

	// The public anchor stays disclosable whatever is installed.
	a.hold(1)
	wantDisclosed(t, ks, at(9), 0)
	ks.UnregisterInstalled(a)
	wantDisclosed(t, ks, at(9), 8)
}

// TestLastKeyDisclosedAfterRelease covers the end of the chain: at and after
// Expiry k_{L-1} is disclosed only once the holder released it, and a holder
// that never releases keeps the cap until it is unregistered.
func TestLastKeyDisclosedAfterRelease(t *testing.T) {
	const length = 4
	ks, at := disclosureSchedule(t, length)
	h := &fakeHolder{}
	ks.RegisterInstalled(h)
	h.hold(length - 1)

	for _, when := range []time.Time{ks.Expiry(), ks.Expiry().Add(time.Hour)} {
		wantDisclosed(t, ks, when, length-2)
	}
	h.release()
	wantDisclosed(t, ks, ks.Expiry(), length-1)

	stuck := &fakeHolder{}
	stuck.hold(2)
	ks.RegisterInstalled(stuck)
	wantDisclosed(t, ks, at(length), 1)
	wantDisclosed(t, ks, ks.Expiry().Add(24*time.Hour), 1)
	ks.UnregisterInstalled(stuck)
	wantDisclosed(t, ks, ks.Expiry().Add(24*time.Hour), length-1)
}
