// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

const refreshDelay = 10 * time.Second

var refreshStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func refreshTagger(t *testing.T, epoch time.Time) (*BPFTagger, *observer.ObservedLogs) {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:        bytes.Repeat([]byte{0x3C}, 32),
		ChainLength: 1 << 10,
		Delay:       refreshDelay,
		Epoch:       epoch,
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
	if err := bt.initializeRefresh(update, func() (<-chan time.Time, func()) { return ticks, func() {} }); err != nil {
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
	entries := logs.AllUntimed()
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

// TestApplyKeyRemovesSlotOnFailedInstall pins the install/remove decision
// without a loaded program.
func TestApplyKeyRemovesSlotOnFailedInstall(t *testing.T) {
	usable := refreshStart.Add(2 * refreshDelay)
	errPut, errDelete := errors.New("put failed"), errors.New("delete failed")
	for _, tc := range []struct {
		name              string
		at                time.Time
		putErr, delErr    error
		puts, dels        int
		wantErrs          []error
		stale, recordTime bool
	}{
		{name: "install", at: usable, puts: 1, recordTime: true},
		{name: "failed_install_removes", at: usable, putErr: errPut, puts: 1, dels: 1, wantErrs: []error{errPut}},
		{name: "failed_install_and_remove", at: usable, putErr: errPut, delErr: errDelete, puts: 1, dels: 1, wantErrs: []error{errPut, errDelete}, stale: true},
		{name: "no_key_removes", at: refreshStart, dels: 1},
		{name: "no_key_failed_remove", at: refreshStart, delErr: errDelete, dels: 1, wantErrs: []error{errDelete}, stale: true},
		{name: "no_key_absent_slot", at: refreshStart, delErr: ebpf.ErrKeyNotExist, dels: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bt, _ := refreshTagger(t, refreshStart)
			want, _, _ := akEntryAt(bt.schedule, bt.measureID, tc.at)
			puts, dels := 0, 0
			err := bt.applyKeyAt(tc.at, func(e akEntry) error {
				puts++
				if e != want {
					t.Errorf("installed %+v, want %+v", e, want)
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
		})
	}
}
