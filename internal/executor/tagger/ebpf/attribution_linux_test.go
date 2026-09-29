// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"testing"
	"time"

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
