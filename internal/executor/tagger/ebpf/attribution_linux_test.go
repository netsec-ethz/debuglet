// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// TestRefreshFailureMakesAttributionUnavailable drives the refresh loop by
// hand and reads the schedule's attribution after each update: a failed
// install is unavailable with its error while the previous key stays held, and
// the next successful refresh makes it available again.
func TestRefreshFailureMakesAttributionUnavailable(t *testing.T) {
	bt, _ := refreshTagger(t, time.Now().Add(-time.Minute))
	errPut, errDelete := errors.New("put failed"), errors.New("delete failed")
	type outcome struct{ put, del error }
	results := []outcome{{}, {errPut, errDelete}, {}}
	calls := 0
	update := func() error {
		r := results[calls]
		calls++
		return bt.applyKeyAt(time.Now(), func(akEntry) error { return r.put }, func() error { return r.del })
	}
	ticks, waiting := make(chan time.Time), make(chan error)
	newTimer := func(lastErr error) (<-chan time.Time, func()) {
		waiting <- lastErr
		return ticks, func() {}
	}
	errs := make(chan error, 1)
	go func() { errs <- bt.initializeRefresh(update, newTimer) }()
	<-waiting // The initial install succeeded and the loop waits.
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	schedule := bt.Schedule()
	if a := schedule.Attribution(time.Now()); a.Reason != "" || !a.Installed || a.LastInstall.IsZero() {
		t.Fatalf("after initial install: %+v", a)
	}

	ticks <- time.Now()
	if err := <-waiting; !errors.Is(err, errStaleKey) {
		t.Fatalf("refresh error %v, want a stale key", err)
	}
	a := schedule.Attribution(time.Now())
	if a.Reason != tesla.UnattributableRefreshFailing || !errors.Is(a.RefreshErr, errPut) || !a.Installed {
		t.Fatalf("after failed refresh: %+v", a)
	}

	ticks <- time.Now()
	if err := <-waiting; err != nil {
		t.Fatal(err)
	}
	if a := schedule.Attribution(time.Now()); a.Reason != "" || a.RefreshErr != nil {
		t.Fatalf("after recovery: %+v", a)
	}
	close(bt.stopCh)
	waitRefresh(t, bt.refreshDone)
}

// suspendClock treats an instant as its monotonic reading; from the instant
// resume on, the wall clock is ahead by the suspended time.
type suspendClock struct {
	resume    time.Time
	suspended time.Duration
}

func (c suspendClock) Elapsed(origin, t time.Time) (time.Duration, time.Duration) {
	monotonic := t.Sub(origin)
	if t.Before(c.resume) {
		return monotonic, monotonic
	}
	return monotonic, monotonic + c.suspended
}

// TestClockDriftRemovesInstalledKey checks the kernel path under drift: the
// slot keeps the key it holds until the next refresh, at most one epoch, and
// that refresh removes it and releases the hold instead of installing a key.
func TestClockDriftRemovesInstalledKey(t *testing.T) {
	resume := refreshStart.Add(3*refreshEpoch + time.Second)
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x3C}, 32), ChainLength: 1 << 10, EpochLength: refreshEpoch,
		DisclosureDelay: refreshDisclosure, Epoch: refreshStart, Clock: suspendClock{resume: resume, suspended: 30 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	bt := &BPFTagger{logger: zap.NewNop(), schedule: ks, measureID: []byte("measurement-refresh")}
	ks.RegisterInstalled(bt)
	filled, removes := false, 0
	put := func(akEntry) error { filled = true; return nil }
	del := func() error { filled = false; removes++; return nil }

	if err := bt.applyKeyAt(refreshStart.Add(3*refreshEpoch), put, del); err != nil || !filled {
		t.Fatalf("install before the suspend: err=%v filled=%v", err, filled)
	}
	if a := ks.Attribution(resume); a.Reason != tesla.UnattributableClockDrift || !a.Installed || a.InstalledEpoch != 3 {
		t.Fatalf("after resume, before the refresh: %+v", a)
	}

	boundary := refreshStart.Add(4 * refreshEpoch)
	if err := bt.applyKeyAt(boundary, put, del); err != nil || filled || removes != 1 {
		t.Fatalf("refresh under drift: err=%v filled=%v removes=%d", err, filled, removes)
	}
	if _, held := bt.InstalledEpoch(); held {
		t.Fatal("hold kept after the slot was removed")
	}
	if a := ks.Attribution(boundary); a.Reason != tesla.UnattributableClockDrift || a.Installed {
		t.Fatalf("after the refresh: %+v", a)
	}
	if idx, _, _ := ks.DisclosedKey(boundary); idx != 4-refreshDisclosure {
		t.Fatalf("disclosed %d, want %d", idx, 4-refreshDisclosure)
	}
	if wait, due := refreshWait(ks, boundary, false, false); !due || wait != refreshEpoch {
		t.Fatalf("next refresh %v,%v, want the next boundary", wait, due)
	}
}
