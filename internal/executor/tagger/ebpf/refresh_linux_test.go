// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// refreshEpoch is the epoch length of the refresh fixtures and
// refreshDisclosure their disclosure delay d, the shortest allowed, so an
// installed key two epochs behind caps disclosure.
const (
	refreshEpoch      = 10 * time.Second
	refreshDisclosure = tesla.MinDisclosureDelay
)

var refreshStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func refreshTagger(t *testing.T, epoch time.Time) (*BPFTagger, *observer.ObservedLogs) {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:            bytes.Repeat([]byte{0x3C}, 32),
		ChainLength:     1 << 10,
		EpochLength:     refreshEpoch,
		DisclosureDelay: refreshDisclosure,
		Epoch:           epoch,
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	core, logs := observer.New(zapcore.DebugLevel)
	return &BPFTagger{
		logger:    zap.New(core),
		schedule:  ks,
		measureID: []byte("measurement-refresh"),
		stopCh:    make(chan struct{}),
	}, logs
}

func (bt *BPFTagger) refreshState() (error, time.Time) {
	bt.refreshMu.Lock()
	defer bt.refreshMu.Unlock()
	return bt.refreshErr, bt.lastInstall
}

// TestKeyRefreshRetainsAndLogsFailureChanges drives the refresh loop by hand:
// a repeated failure is logged once, a changed failure again, and the next
// successful refresh once more.
func TestKeyRefreshRetainsAndLogsFailureChanges(t *testing.T) {
	bt, logs := refreshTagger(t, time.Now().Add(-time.Minute))
	errFull, errBusy := errors.New("map full"), errors.New("map busy")
	results := []error{nil, errFull, errFull, errBusy, nil}
	calls, removes := 0, 0
	update := func() error {
		return bt.applyKeyAt(time.Now(), func(akEntry) error {
			err := results[calls]
			calls++
			return err
		}, func() error { removes++; return nil })
	}
	ticks := make(chan time.Time)
	if err := bt.initializeRefresh(update, func(error) (<-chan time.Time, func()) { return ticks, func() {} }); err != nil {
		t.Fatal(err)
	}
	_, initial := bt.refreshState()
	if initial.IsZero() {
		t.Error("initial install time not recorded")
	}
	for i := 0; i < 4; i++ {
		ticks <- time.Now()
	}
	if err := bt.Close(); err != nil {
		t.Fatal(err)
	}
	waitRefresh(t, bt.refreshDone)

	if calls != 5 || removes != 3 {
		t.Errorf("installs=%d removes=%d, want 5 and 3", calls, removes)
	}
	got, last := bt.refreshState()
	if got != nil || !last.After(initial) {
		t.Errorf("retained failure=%v last install=%v (initial %v)", got, last, initial)
	}
	// Close of this map-less fixture logs its own warning, which is not this test's subject.
	entries := logs.FilterMessageSnippet("eBPF key refresh").AllUntimed()
	if len(entries) != 3 {
		t.Fatalf("got %d log lines, want 3: %+v", len(entries), entries)
	}
	for i, want := range []struct {
		level zapcore.Level
		err   error
	}{{zapcore.WarnLevel, errFull}, {zapcore.WarnLevel, errBusy}, {zapcore.InfoLevel, nil}} {
		e := entries[i]
		fields := e.ContextMap()
		if e.Level != want.level {
			t.Errorf("line %d level=%v, want %v", i, e.Level, want.level)
		}
		if _, ok := fields["last_install"]; !ok {
			t.Errorf("line %d does not name the last install: %v", i, fields)
		}
		if msg, _ := fields["error"].(string); want.err != nil && !bytes.Contains([]byte(msg), []byte(want.err.Error())) {
			t.Errorf("line %d error=%q, want %q", i, msg, want.err)
		}
	}
	if at := entries[2].ContextMap()["last_install"].(time.Time); !at.Equal(last) {
		t.Errorf("success line names %v, want %v", at, last)
	}
}

// TestApplyKeyRemovesSlotOnFailedInstall pins the install/remove decision and
// the hold without a loaded program: the hold is claimed before the slot is
// written, keeps the older epoch while a write is in flight, and is released
// only after the slot is confirmed empty.
func TestApplyKeyRemovesSlotOnFailedInstall(t *testing.T) {
	usable := refreshStart.Add(2 * refreshEpoch)
	errPut, errDelete := errors.New("put failed"), errors.New("delete failed")
	for _, tc := range []struct {
		name              string
		at                time.Time
		putErr, delErr    error
		puts, dels        int
		wantErrs          []error
		stale, recordTime bool
		// prior is the epoch already held before the update, 0 for none; hold
		// is the epoch held while install runs and after the update.
		prior, during, hold int64
	}{
		{name: "install", at: usable, puts: 1, recordTime: true, during: 2, hold: 2},
		{name: "install_moves_prior", at: usable, puts: 1, recordTime: true, prior: 1, during: 1, hold: 2},
		{name: "failed_install_removes", at: usable, putErr: errPut, puts: 1, dels: 1, wantErrs: []error{errPut}, during: 2},
		{name: "failed_install_and_remove", at: usable, putErr: errPut, delErr: errDelete, puts: 1, dels: 1, wantErrs: []error{errPut, errDelete}, stale: true, during: 2, hold: 2},
		{name: "failed_install_and_remove_keeps_prior", at: usable, putErr: errPut, delErr: errDelete, puts: 1, dels: 1, wantErrs: []error{errPut, errDelete}, stale: true, prior: 1, during: 1, hold: 1},
		{name: "no_key_removes", at: refreshStart, dels: 1, prior: 1},
		{name: "no_key_failed_remove", at: refreshStart, delErr: errDelete, dels: 1, wantErrs: []error{errDelete}, stale: true, prior: 1, hold: 1},
		{name: "no_key_absent_slot", at: refreshStart, delErr: ebpf.ErrKeyNotExist, dels: 1, prior: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bt, _ := refreshTagger(t, refreshStart)
			if tc.prior != 0 {
				bt.installedEpoch, bt.holding = tc.prior, true
			}
			want, _, _ := akEntryAt(bt.schedule, bt.measureID, tc.at)
			puts, dels := 0, 0
			err := bt.applyKeyAt(tc.at, func(e akEntry) error {
				puts++
				if e != want {
					t.Errorf("installed %+v, want %+v", e, want)
				}
				if epoch, held := bt.InstalledEpoch(); !held || epoch != tc.during {
					t.Errorf("hold during install=%d,%v, want %d", epoch, held, tc.during)
				}
				return tc.putErr
			}, func() error { dels++; return tc.delErr })
			if puts != tc.puts || dels != tc.dels {
				t.Fatalf("installs=%d removes=%d, want %d and %d", puts, dels, tc.puts, tc.dels)
			}
			if len(tc.wantErrs) == 0 && err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			for _, w := range tc.wantErrs {
				if !errors.Is(err, w) {
					t.Errorf("error %v does not report %v", err, w)
				}
			}
			if errors.Is(err, errStaleKey) != tc.stale {
				t.Errorf("stale key marked=%v, want %v: %v", !tc.stale, tc.stale, err)
			}
			if _, last := bt.refreshState(); last.Equal(tc.at) != tc.recordTime {
				t.Errorf("last install=%v, want recorded=%v", last, tc.recordTime)
			}
			if epoch, held := bt.InstalledEpoch(); held != (tc.hold != 0) || (held && epoch != tc.hold) {
				t.Errorf("hold after update=%d,%v, want %d", epoch, held, tc.hold)
			}
		})
	}
}

// TestDisclosureNeverNamesInstalledKey drives key updates and heartbeats on
// one controlled clock across boundaries and the end of the chain. Whatever
// the refresh timing, the disclosed epoch is never the one whose key the slot
// holds; with boundary-aligned refresh the previous key is disclosed on the
// same instant the new one is installed.
func TestDisclosureNeverNamesInstalledKey(t *testing.T) {
	errBusy := errors.New("map busy")
	for _, tc := range []struct {
		name string
		// next returns the instant of the refresh after one at now.
		next func(ks *tesla.KeySchedule, now time.Time) time.Time
		// Every refresh in [failFrom, failUntil) fails to install and to
		// remove, so the slot keeps the key it held.
		failFrom, failUntil time.Duration
		aligned             bool
	}{
		{name: "boundary", aligned: true, next: func(ks *tesla.KeySchedule, now time.Time) time.Time {
			if at, ok := nextBoundary(ks, now); ok {
				return at
			}
			return now.Add(time.Hour)
		}},
		{name: "late_refresh", next: func(_ *tesla.KeySchedule, now time.Time) time.Time { return now.Add(refreshEpoch / 2) }},
		{name: "failed_refresh", failFrom: 3 * refreshEpoch, failUntil: 9 * refreshEpoch / 2, next: func(_ *tesla.KeySchedule, now time.Time) time.Time { return now.Add(refreshEpoch / 3) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ks, err := tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x3C}, 32), ChainLength: 6, EpochLength: refreshEpoch, DisclosureDelay: refreshDisclosure, Epoch: refreshStart})
			if err != nil {
				t.Fatal(err)
			}
			bt := &BPFTagger{logger: zap.NewNop(), schedule: ks, measureID: []byte("measurement-refresh")}
			ks.RegisterInstalled(bt)
			var slot akEntry
			filled := false
			put := func(e akEntry) error { slot, filled = e, true; return nil }
			del := func() error { filled = false; return nil }
			first := refreshStart.Add(2*refreshEpoch + 9*refreshEpoch/10)
			next := first
			for now := first; !now.After(ks.Expiry().Add(2 * refreshEpoch)); now = now.Add(refreshEpoch / 20) {
				if !now.Before(next) {
					if at := now.Sub(refreshStart); at >= tc.failFrom && at < tc.failUntil {
						fail := func() error { return errBusy }
						_ = bt.applyKeyAt(now, func(akEntry) error { return fail() }, fail)
					} else {
						_ = bt.applyKeyAt(now, put, del)
					}
					next = tc.next(ks, now)
				}
				idx, _, ok := ks.DisclosedKey(now)
				if !ok {
					continue
				}
				if held, usable, _ := akEntryAt(ks, bt.measureID, refreshStart.Add(time.Duration(idx)*refreshEpoch)); filled && usable && held == slot {
					t.Fatalf("at %v: disclosed epoch %d while its key is still installed", now.Sub(refreshStart), idx)
				}
				// Aligned refreshes never hold disclosure back: k_{t-d}, and
				// k_{L-1} at most, whose epoch ended long before.
				if want := min(int64(now.Sub(refreshStart)/refreshEpoch)-refreshDisclosure, ks.ChainLength()-1); tc.aligned && idx != want {
					t.Fatalf("at %v: disclosed epoch %d, want %d", now.Sub(refreshStart), idx, want)
				}
			}
			if filled {
				t.Fatal("slot still holds a key after Expiry")
			}
			if idx, _, _ := ks.DisclosedKey(ks.Expiry().Add(refreshEpoch)); idx != ks.ChainLength()-1 {
				t.Fatalf("after Expiry disclosed %d, want %d", idx, ks.ChainLength()-1)
			}
		})
	}
}

// TestTaggerCloseReleasesHoldOnlyWhenKeyGone checks the hold after Close: it
// is released when the slot delete is confirmed or the attachment is closed,
// and kept, still capping disclosure, when the program may still tag with it.
func TestTaggerCloseReleasesHoldOnlyWhenKeyGone(t *testing.T) {
	errDelete, errDetach := errors.New("delete failed"), errors.New("detach failed")
	for _, tc := range []struct {
		name              string
		delErr, detachErr error
		released          bool
	}{
		{name: "deleted", released: true},
		{name: "absent", delErr: ebpf.ErrKeyNotExist, released: true},
		{name: "deleted_detach_failed", detachErr: errDetach, released: true},
		{name: "detached", delErr: errDelete, released: true},
		{name: "still_attached", delErr: errDelete, detachErr: errDetach},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bt, _ := refreshTagger(t, refreshStart)
			attach, program := &refreshCloser{err: tc.detachErr}, &refreshCloser{}
			bt.closers = []io.Closer{attach, program}
			bt.schedule.RegisterInstalled(bt)
			if err := bt.applyKeyAt(refreshStart.Add(2*refreshEpoch), func(akEntry) error { return nil }, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			later := refreshStart.Add(6 * refreshEpoch)
			if idx, _, _ := bt.schedule.DisclosedKey(later); idx != 1 {
				t.Fatalf("disclosed %d with epoch 2 installed, want 1", idx)
			}
			const due = 6 - refreshDisclosure
			removes := 0
			err := bt.closeWith(func() error { removes++; return tc.delErr })
			if removes != 1 || attach.calls.Load() != 1 || program.calls.Load() != 1 {
				t.Fatalf("removes=%d releases=%d,%d", removes, attach.calls.Load(), program.calls.Load())
			}
			if (tc.detachErr != nil) != errors.Is(err, errDetach) {
				t.Fatalf("Close=%v, want detach error %v", err, tc.detachErr)
			}
			_, held := bt.InstalledEpoch()
			idx, _, _ := bt.schedule.DisclosedKey(later)
			if held == tc.released || (idx == due) != tc.released {
				t.Fatalf("after Close hold=%v disclosed=%d, want released=%v", held, idx, tc.released)
			}
			if again := bt.closeWith(func() error { removes++; return nil }); removes != 1 || !errors.Is(again, err) {
				t.Fatalf("repeat Close removes=%d err=%v", removes, again)
			}
		})
	}
}

// TestRefreshWaitRetriesFailedUpdates pins the timer choice: the next boundary
// after a success, a retry within the epoch after a failure, and after Expiry
// retries only while the slot may still hold a key.
func TestRefreshWaitRetriesFailedUpdates(t *testing.T) {
	bt, _ := refreshTagger(t, refreshStart)
	ks := bt.schedule
	mid := refreshStart.Add(2*refreshEpoch + time.Second)
	late := refreshStart.Add(3*refreshEpoch - 2*time.Second)
	expired := ks.Expiry().Add(time.Second)
	for _, tc := range []struct {
		name            string
		at              time.Time
		failed, holding bool
		wait            time.Duration
		due             bool
	}{
		{name: "success_waits_for_boundary", at: mid, holding: true, wait: refreshEpoch - time.Second, due: true},
		{name: "failure_retried_mid_epoch", at: mid, failed: true, holding: true, wait: refreshEpoch / 2, due: true},
		{name: "failure_retried_at_boundary", at: late, failed: true, holding: true, wait: 2 * time.Second, due: true},
		{name: "expired_released_idles", at: expired},
		{name: "expired_failed_removal_retried", at: expired, failed: true, holding: true, wait: refreshEpoch / 2, due: true},
		{name: "expired_failure_without_hold_idles", at: expired, failed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wait, due := refreshWait(ks, tc.at, tc.failed, tc.holding)
			if due != tc.due || wait != tc.wait {
				t.Fatalf("refreshWait=%v,%v, want %v,%v", wait, due, tc.wait, tc.due)
			}
		})
	}
}

// TestKeyRefreshRetriesFailedUpdates drives the refresh loop on a controlled
// clock: a failed update at a boundary is retried before the next boundary, a
// failed removal at Expiry is retried, and once it succeeds the hold is
// released, the last key is disclosed and the loop idles.
func TestKeyRefreshRetriesFailedUpdates(t *testing.T) {
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x3C}, 32), ChainLength: 4, EpochLength: refreshEpoch, DisclosureDelay: refreshDisclosure, Epoch: refreshStart})
	if err != nil {
		t.Fatal(err)
	}
	bt := &BPFTagger{logger: zap.NewNop(), schedule: ks, measureID: []byte("measurement-refresh"), stopCh: make(chan struct{})}
	errBusy := errors.New("map busy")
	var now time.Time
	var putErr, delErr error
	update := func() error {
		return bt.applyKeyAt(now, func(akEntry) error { return putErr }, func() error { return delErr })
	}
	type due struct {
		wait time.Duration
		ok   bool
	}
	ticks, waits := make(chan time.Time), make(chan due, 1)
	newTimer := func(lastErr error) (<-chan time.Time, func()) {
		_, holding := bt.InstalledEpoch()
		wait, ok := refreshWait(ks, now, lastErr != nil, holding)
		waits <- due{wait, ok}
		return ticks, func() {}
	}
	now = refreshStart.Add(2*refreshEpoch + time.Second)
	if err := bt.initializeRefresh(update, newTimer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bt.Close(); waitRefresh(t, bt.refreshDone) })
	for _, step := range []struct {
		name           string
		at             time.Duration
		putErr, delErr error
		hold           int64 // 0: no key held
		next           due
	}{
		{name: "initial", at: 2*refreshEpoch + time.Second, hold: 2, next: due{refreshEpoch - time.Second, true}},
		{name: "failed_at_boundary", at: 3 * refreshEpoch, putErr: errBusy, delErr: errBusy, hold: 2, next: due{refreshEpoch / 2, true}},
		{name: "retry_succeeds", at: 3*refreshEpoch + refreshEpoch/2, hold: 3, next: due{refreshEpoch / 2, true}},
		{name: "failed_removal_at_expiry", at: 4 * refreshEpoch, delErr: errBusy, hold: 3, next: due{refreshEpoch / 2, true}},
		{name: "removal_retried", at: 4*refreshEpoch + refreshEpoch/2, next: due{0, false}},
	} {
		if step.name != "initial" {
			now, putErr, delErr = refreshStart.Add(step.at), step.putErr, step.delErr
			ticks <- now
		}
		var got due
		select {
		case got = <-waits:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: loop armed no timer", step.name)
		}
		if got != step.next {
			t.Fatalf("%s: next update due=%+v, want %+v", step.name, got, step.next)
		}
		if epoch, held := bt.InstalledEpoch(); held != (step.hold != 0) || (held && epoch != step.hold) {
			t.Fatalf("%s: hold=%d,%v, want %d", step.name, epoch, held, step.hold)
		}
		// Long after the delay elapsed, a held key still caps disclosure.
		if idx, _, _ := ks.DisclosedKey(ks.Expiry().Add(time.Hour)); step.hold != 0 && idx != step.hold-1 {
			t.Fatalf("%s: disclosed %d with epoch %d held, want %d", step.name, idx, step.hold, step.hold-1)
		}
	}
	if idx, _, _ := ks.DisclosedKey(refreshStart.Add((3 + refreshDisclosure) * refreshEpoch)); idx != 3 {
		t.Fatalf("after the retried removal disclosed %d, want 3", idx)
	}
}
