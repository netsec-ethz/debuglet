// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"errors"
	"testing"
	"time"
)

// reportingHolder is a fakeHolder that also reports its refresh outcome.
type reportingHolder struct {
	fakeHolder
	last time.Time
	err  error
}

func (h *reportingHolder) LastRefresh() (time.Time, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last, h.err
}

func (h *reportingHolder) refreshed(at time.Time, err error) {
	h.mu.Lock()
	if err == nil {
		h.last = at
	}
	h.err = err
	h.mu.Unlock()
}

// TestAttributionFollowsEpochAndChainBounds checks the schedule alone: epoch 0
// and any instant before Epoch are unattributable because k_0 is public, epoch
// 1 is the first attributable one, and from Expiry the chain is exhausted.
func TestAttributionFollowsEpochAndChainBounds(t *testing.T) {
	ks, at := disclosureSchedule(t, 4)
	for _, tc := range []struct {
		name   string
		at     time.Time
		reason string
	}{
		{"before_epoch", at(0).Add(-time.Second), UnattributableEpochZero},
		{"epoch_zero", at(0), UnattributableEpochZero},
		{"epoch_zero_end", at(1).Add(-time.Nanosecond), UnattributableEpochZero},
		{"first_epoch", at(1), ""},
		{"last_epoch", at(3), ""},
		{"expiry", at(4), UnattributableChainExhausted},
		{"after_expiry", at(9), UnattributableChainExhausted},
	} {
		if got := ks.Attribution(tc.at); got.Reason != tc.reason || got.Installed || !got.HeldSince.IsZero() {
			t.Errorf("%s: %+v, want reason %q and no holder state", tc.name, got, tc.reason)
		}
	}
}

// TestAttributionReportsRefreshFailureAndHold drives two holders across a
// boundary: a failed refresh is unavailable with its error at once, the hold
// it leaves is reported from the boundary, and only a hold longer than one
// epoch is unavailable on its own. A holder without refresh reporting still
// caps the installed epoch and the hold.
func TestAttributionReportsRefreshFailureAndHold(t *testing.T) {
	ks, at := disclosureSchedule(t, 1<<10)
	failing, plain := &reportingHolder{}, &fakeHolder{}
	ks.RegisterInstalled(failing)
	ks.RegisterInstalled(plain)
	failing.hold(4)
	failing.refreshed(at(4), nil)
	plain.hold(4)

	a := ks.Attribution(at(4).Add(time.Second))
	if a.Reason != "" || !a.Installed || a.InstalledEpoch != 4 || !a.LastInstall.Equal(at(4)) || !a.HeldSince.IsZero() {
		t.Fatalf("steady state: %+v", a)
	}

	// The boundary refresh fails: the slot may still hold k_4.
	errPut := errors.New("put failed")
	plain.hold(5)
	failing.refreshed(at(5), errPut)
	a = ks.Attribution(at(5).Add(time.Second))
	if a.Reason != UnattributableRefreshFailing || !errors.Is(a.RefreshErr, errPut) || a.InstalledEpoch != 4 ||
		!a.HeldSince.Equal(at(5)) || !a.LastInstall.Equal(at(4)) {
		t.Fatalf("failed refresh: %+v", a)
	}

	// A stuck holder that no longer reports a failure, such as a tagger
	// whose removal failed at Close, is ordinary for one epoch and then not.
	failing.mu.Lock()
	failing.err = nil
	failing.mu.Unlock()
	if a = ks.Attribution(at(5).Add(ks.MaxDisclosureHold())); a.Reason != "" || !a.HeldSince.Equal(at(5)) {
		t.Fatalf("hold within bound: %+v", a)
	}
	if a = ks.Attribution(at(5).Add(ks.MaxDisclosureHold() + time.Second)); a.Reason != UnattributableDisclosureHeld || !a.HeldSince.Equal(at(5)) {
		t.Fatalf("hold beyond bound: %+v", a)
	}

	// The plain holder caps the installed epoch like any other.
	failing.hold(6)
	if a = ks.Attribution(at(6)); a.InstalledEpoch != 5 || !a.HeldSince.Equal(at(6)) || a.Reason != "" {
		t.Fatalf("plain holder: %+v", a)
	}
	failing.release()
	plain.release()
	if a = ks.Attribution(at(6)); a.Installed || !a.HeldSince.IsZero() || a.Reason != "" {
		t.Fatalf("released: %+v", a)
	}
}
