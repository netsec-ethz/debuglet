// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

func TestDrainPreservesInFlightAdmissionAndWaitsForFinalization(t *testing.T) {
	persisting, finishPersist := make(chan struct{}), make(chan struct{})
	finalizing, finishFinalize := make(chan struct{}), make(chan struct{})
	var persistOnce, finalizeOnce sync.Once
	releasePersist := func() { persistOnce.Do(func() { close(finishPersist) }) }
	releaseFinalize := func() { finalizeOnce.Do(func() { close(finishFinalize) }) }
	m := newTestPersistentStorage(t, func(_ context.Context, s scheduler.Spec) (scheduler.Spec, error) {
		close(persisting)
		<-finishPersist
		return s, nil
	}, func(context.Context, uuid.UUID) error {
		close(finalizing)
		<-finishFinalize
		return nil
	}, nil)
	h := newLoopHarness(t, m)
	t.Cleanup(releasePersist)
	t.Cleanup(releaseFinalize)
	started := make(chan struct{})
	m.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
		close(started)
		<-h.release
		return scheduler.Completion{}
	})
	insertDone := make(chan struct{})
	var insertErr error
	go func() {
		insertErr = m.Insert(context.Background(), distinctSpecs(1)[0])
		close(insertDone)
	}()
	if !await(t, persisting, "accepted persistence reservation") {
		return
	}
	if m.TryDrain() {
		t.Fatal("idle drain ignored in-flight persistence")
	}
	m.BeginDrain()
	m.BeginDrain()
	if m.IsDrained() {
		t.Fatal("drained while an insertion still owns persistence")
	}
	if err := m.Insert(context.Background(), distinctSpecs(1)[0]); !errors.Is(err, scheduler.ErrDraining) {
		t.Fatalf("new admission during drain = %v", err)
	}
	releasePersist()
	if !await(t, insertDone, "reserved insertion") {
		return
	}
	if insertErr != nil || m.IsDrained() {
		t.Fatalf("accepted insertion changed: error=%v drained=%t", insertErr, m.IsDrained())
	}
	h.start()
	if !await(t, started, "accepted run during drain") {
		return
	}
	if m.IsDrained() {
		t.Fatal("drained while the accepted callback is running")
	}
	h.unblockCallbacks()
	if !await(t, finalizing, "run finalization") {
		return
	}
	if m.IsDrained() {
		t.Fatal("drained before canonical finalization joined")
	}
	releaseFinalize()
	if !waitFor(t, "successful graceful drain", m.IsDrained) {
		return
	}
	if closed(h.loopDone) {
		t.Fatal("graceful drain stopped the scheduler loop")
	}
}

func TestDrainStillStartsAcceptedFutureRun(t *testing.T) {
	m := newTestStorage(t)
	clock := newManualClock()
	m.clock = clock
	h := newLoopHarness(t, m)
	started := make(chan scheduler.Spec, 1)
	m.RegisterOnStart(func(_ context.Context, spec scheduler.Spec) scheduler.Completion {
		started <- spec
		return scheduler.Completion{}
	})
	spec := distinctSpecs(1)[0]
	at := clock.Now().Add(time.Hour)
	spec.StartTime = &at
	if err := m.Insert(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	m.BeginDrain()
	h.start()
	if !clock.armed(t, at) {
		return
	}
	if m.IsDrained() {
		t.Fatal("queued future run was omitted from drain")
	}
	assertNoCallback(t, started)
	clock.advance(at)
	if !callbackID(t, started, spec.DebugletID) {
		return
	}
	waitFor(t, "scheduled run completion", m.IsDrained)
}

func TestDrainFailureDoesNotPermitRenewal(t *testing.T) {
	for _, stage := range []string{"cleanup", "finalization"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("retained cleanup failure")
			m := newTestPersistentStorage(t, nil, func(context.Context, uuid.UUID) error {
				if stage == "finalization" {
					return failure
				}
				return nil
			}, nil)
			ctx, cancel := context.WithCancel(context.Background())
			loopDone := make(chan error, 1)
			m.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
				if stage == "cleanup" {
					return scheduler.Completion{CleanupErr: failure}
				}
				return scheduler.Completion{}
			})
			spec := distinctSpecs(1)[0]
			if err := m.Insert(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
			m.BeginDrain()
			go func() { loopDone <- m.StartLoop(ctx) }()
			t.Cleanup(func() {
				cancel()
				joined, done := context.WithTimeout(context.Background(), testBound)
				defer done()
				if err := m.Shutdown(joined); !errors.Is(err, failure) {
					t.Errorf("shutdown lost cleanup failure: %v", err)
				}
				select {
				case err := <-loopDone:
					if !errors.Is(err, context.Canceled) && !errors.Is(err, scheduler.ErrClosed) {
						t.Error(err)
					}
				case <-joined.Done():
					t.Error("scheduler loop did not join")
				}
			})
			if !waitFor(t, "failed owner retained", func() bool {
				m.mu.RLock()
				defer m.mu.RUnlock()
				o := m.owners[spec.DebugletID]
				return o != nil && o.phase == completed && m.busy == 0
			}) {
				return
			}
			if m.IsDrained() {
				t.Fatal("failed cleanup was treated as a drained scheduler")
			}
		})
	}
}

func TestDrainEmptyIsIdempotentAndDoesNotShutdown(t *testing.T) {
	m := newTestStorage(t)
	h := newLoopHarness(t, m)
	m.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion { return scheduler.Completion{} })
	if m.IsDrained() {
		t.Fatal("empty scheduler was drained before admission closed")
	}
	h.start()
	if !waitFor(t, "running empty scheduler", func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.loopRunning
	}) {
		return
	}
	m.BeginDrain()
	m.BeginDrain()
	if !m.IsDrained() || closed(h.loopDone) {
		t.Fatal("empty drain did not leave the scheduler loop alive")
	}
}

func TestTryDrainLeavesQueuedWorkAndAdmissionOpen(t *testing.T) {
	m := newTestStorage(t)
	h := newLoopHarness(t, m)
	completed := make(chan scheduler.Spec, 2)
	m.RegisterOnStart(func(_ context.Context, spec scheduler.Spec) scheduler.Completion {
		completed <- spec
		return scheduler.Completion{}
	})
	specs := distinctSpecs(2)
	if err := m.Insert(context.Background(), specs[0]); err != nil {
		t.Fatal(err)
	}
	if m.TryDrain() {
		t.Fatal("idle drain accepted a queued run")
	}
	if err := m.Insert(context.Background(), specs[1]); err != nil {
		t.Fatalf("failed idle drain closed admission: %v", err)
	}
	h.start()
	want := map[uuid.UUID]bool{specs[0].DebugletID: true, specs[1].DebugletID: true}
	for range specs {
		select {
		case spec := <-completed:
			if !want[spec.DebugletID] {
				t.Fatal("idle drain changed or repeated accepted work")
			}
			delete(want, spec.DebugletID)
		case <-time.After(testBound):
			t.Fatal("accepted work did not finish after unsuccessful idle drain")
		}
	}
	if !waitFor(t, "idle drain after accepted work", m.TryDrain) || !m.IsDrained() {
		t.Fatal("idle drain did not close admission after accepted work completed")
	}
	if err := m.Insert(context.Background(), distinctSpecs(1)[0]); !errors.Is(err, scheduler.ErrDraining) {
		t.Fatalf("successful idle drain admitted new work: %v", err)
	}
}

func TestTryDrainAtomicallyExcludesNewInsertion(t *testing.T) {
	for i := 0; i < 64; i++ {
		m := newTestStorage(t)
		gate := make(chan struct{})
		inserted := make(chan error, 1)
		drained := make(chan bool, 1)
		go func() {
			<-gate
			inserted <- m.Insert(context.Background(), distinctSpecs(1)[0])
		}()
		go func() {
			<-gate
			drained <- m.TryDrain()
		}()
		close(gate)
		var drain bool
		select {
		case drain = <-drained:
		case <-time.After(testBound):
			t.Fatal("idle drain blocked")
		}
		var err error
		select {
		case err = <-inserted:
		case <-time.After(testBound):
			t.Fatal("racing insertion blocked")
		}
		if drain {
			if !errors.Is(err, scheduler.ErrDraining) || !m.IsDrained() {
				t.Fatalf("drain and insertion both won: error=%v drained=%t", err, m.IsDrained())
			}
		} else if err != nil || m.IsDrained() {
			t.Fatalf("accepted insertion lost: error=%v drained=%t", err, m.IsDrained())
		}
		if err := m.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}
