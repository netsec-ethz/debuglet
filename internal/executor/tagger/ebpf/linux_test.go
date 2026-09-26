// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

func TestBPFLinuxLoad(t *testing.T) {
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  make([]byte, 32),
		Delay: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}

	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName failed: %v", err)
	}

	bt, err := NewBPFTagger(zap.NewNop(), iface, ks, []byte("test-measurement"))
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("NewBPFTagger failed: %v", err)
	}
	defer bt.Close()

	if bt.MapKey() == 0 {
		t.Error("MapKey() returned 0")
	}

	pkt := []byte("dummy-packet")
	result, err := bt.TagPacket(pkt)
	if err != nil {
		t.Errorf("TagPacket failed: %v", err)
	}
	if string(result) != string(pkt) {
		t.Error("TagPacket unexpectedly modified packet")
	}
}

type refreshCloser struct {
	calls atomic.Int32
	err   error
}

func (c *refreshCloser) Close() error { c.calls.Add(1); return c.err }

func waitRefresh(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tagger lifecycle did not join")
	}
}

func TestTaggerCloseJoinsRefreshBeforeResourceRelease(t *testing.T) {
	sentinel := errors.New("resource release failed")
	first, second := &refreshCloser{err: sentinel}, &refreshCloser{}
	bt := &BPFTagger{stopCh: make(chan struct{}), closers: []io.Closer{first, second}}
	ticks := make(chan time.Time, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var updates atomic.Int32
	var timerStops atomic.Int32
	if err := bt.initializeRefresh(func() error {
		if updates.Add(1) > 1 {
			close(entered)
			<-release
		}
		return nil
	}, func() (<-chan time.Time, func()) { return ticks, func() { timerStops.Add(1) } }); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var callers sync.WaitGroup
	t.Cleanup(func() { unblock(); _ = bt.Close(); waitRefresh(t, bt.refreshDone); waitRefresh(t, done) })
	for i := 0; i < 8; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-entered
			if !errors.Is(bt.Close(), sentinel) {
				t.Error("cached Close error lost")
			}
		}()
	}
	go func() { callers.Wait(); close(done) }()
	ticks <- time.Now()
	waitRefresh(t, entered)
	waitRefresh(t, bt.stopCh)
	if first.calls.Load() != 0 || second.calls.Load() != 0 {
		t.Fatal("BPF resources released during active refresh")
	}
	select {
	case <-done:
		t.Fatal("Close did not join held refresh")
	case <-time.After(20 * time.Millisecond):
		// Give a broken non-joining Close time to return while refresh is held.
	}
	unblock()
	waitRefresh(t, done)
	if first.calls.Load() != 1 || second.calls.Load() != 1 || timerStops.Load() != 1 {
		t.Fatalf("release counts=%d,%d timer=%d", first.calls.Load(), second.calls.Load(), timerStops.Load())
	}
	if err := bt.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("repeat Close=%v", err)
	}
}

func TestTaggerInitialUpdateFailureDoesNotWaitForUnstartedRefresh(t *testing.T) {
	initErr, releaseErr := errors.New("initial key failure"), errors.New("map release failure")
	first, second, third := &refreshCloser{err: releaseErr}, &refreshCloser{}, &refreshCloser{}
	bt := &BPFTagger{stopCh: make(chan struct{}), closers: []io.Closer{first, second, third}}
	done := make(chan struct{})
	var got error
	go func() {
		defer close(done)
		got = bt.initializeRefresh(func() error { return initErr }, func() (<-chan time.Time, func()) {
			t.Error("ticker created after initial failure")
			return make(chan time.Time), func() {}
		})
	}()
	waitRefresh(t, done)
	if !errors.Is(got, initErr) || !errors.Is(got, releaseErr) {
		t.Fatalf("initial failure=%v", got)
	}
	if cleanup := CleanupError(got); !errors.Is(cleanup, releaseErr) || errors.Is(cleanup, initErr) {
		t.Fatalf("initial update cleanup classification: %v", cleanup)
	}
	if bt.refreshDone != nil {
		t.Fatal("unstarted refresh acquired a join owner")
	}
	if first.calls.Load() != 1 || second.calls.Load() != 1 || third.calls.Load() != 1 {
		t.Fatalf("releases=%d,%d,%d", first.calls.Load(), second.calls.Load(), third.calls.Load())
	}
	if err := bt.Close(); !errors.Is(err, releaseErr) {
		t.Fatalf("repeat cleanup=%v", err)
	}
	if first.calls.Load() != 1 || second.calls.Load() != 1 || third.calls.Load() != 1 {
		t.Fatal("initial rollback repeated resource release")
	}
}

// The same rollback helper is called by NewBPFTagger after actual object load.
// Fake closers make failing releases observable without requiring kernel access.
func TestTaggerAttachFailureReleasesEveryObject(t *testing.T) {
	attachErr, programErr, mapErr := errors.New("TCX attach failure"), errors.New("program release failure"), errors.New("map release failure")
	for _, rollbackFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean_rollback", true: "failed_rollback"}[rollbackFails], func(t *testing.T) {
			program, mapping := &refreshCloser{}, &refreshCloser{}
			if rollbackFails {
				program.err, mapping.err = programErr, mapErr
			}
			attached, err := attachWithRollback(func() (io.Closer, error) { return nil, attachErr }, program, mapping)
			if attached != nil || !errors.Is(err, attachErr) {
				t.Fatalf("attach result=%v,%v", attached, err)
			}
			if program.calls.Load() != 1 || mapping.calls.Load() != 1 {
				t.Fatalf("rollback stopped early: program=%d map=%d", program.calls.Load(), mapping.calls.Load())
			}
			cleanup := CleanupError(err)
			if rollbackFails {
				if !errors.Is(err, programErr) || !errors.Is(err, mapErr) || !errors.Is(cleanup, programErr) || !errors.Is(cleanup, mapErr) || errors.Is(cleanup, attachErr) {
					t.Fatalf("lost or conflated rollback errors: %v / %v", err, cleanup)
				}
			} else if cleanup != nil {
				t.Fatalf("ordinary unavailable TCX became cleanup failure: %v", cleanup)
			}
		})
	}
}

type rollbackLink struct {
	link.Link
	refreshCloser
}

func (l *rollbackLink) Close() error { return l.refreshCloser.Close() }

func TestTaggerAttachTransfersOwnershipOnlyOnSuccess(t *testing.T) {
	attachErr, linkErr := errors.New("attach failure"), errors.New("link release failure")
	for _, succeeds := range []bool{false, true} {
		name := "partial_attachment_failure"
		if succeeds {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			attached := &rollbackLink{refreshCloser: refreshCloser{err: linkErr}}
			program, mapping := &refreshCloser{}, &refreshCloser{}
			got, err := attachWithRollback(func() (io.Closer, error) {
				if succeeds {
					return attached, nil
				}
				return attached, attachErr
			}, program, mapping)
			if succeeds {
				if got != attached || err != nil {
					t.Fatalf("successful attachment=%v,%v", got, err)
				}
				if attached.calls.Load() != 0 || program.calls.Load() != 0 || mapping.calls.Load() != 0 {
					t.Fatal("successful attachment released transferred resources")
				}
				bt := &BPFTagger{closers: []io.Closer{got, program, mapping}}
				if !errors.Is(bt.Close(), linkErr) || !errors.Is(bt.Close(), linkErr) {
					t.Fatal("transferred cleanup error lost")
				}
			} else if got != nil || !errors.Is(err, attachErr) || !errors.Is(CleanupError(err), linkErr) {
				t.Fatalf("partial attachment=%v,%v", got, err)
			}
			if attached.calls.Load() != 1 || program.calls.Load() != 1 || mapping.calls.Load() != 1 {
				t.Fatalf("owned release counts=%d,%d,%d", attached.calls.Load(), program.calls.Load(), mapping.calls.Load())
			}
		})
	}
}
