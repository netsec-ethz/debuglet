// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package memory is the in-memory admission core both executor schedulers use.
//
// Each accepted run has exactly one owner record while the executor holds it. It
// carries the run's spec and its immutable control binding, the phase it is in
// (persisting, queued, cancel-pending, active, finalizing, completed, retired)
// and the channels its result is published on. One mutex guards all of it, and
// persistence, callbacks and finalization always run outside that mutex.
//
// Both transitions that create work are committed through an admission guard:
// while the core holds its mutex, the guard decides whether the run's binding is
// still armed and calls the commit it was given, which appends the queue entry or
// promotes it to a running one. A guard that refuses leaves the owner and its
// canonical row exactly as they were, so a lost lease never retracts accepted
// work or starts unauthorized work.
//
// Shutdown closes admission and joins what this core owns: reservations,
// callbacks, finalizers and backend reads, each counted while it runs. It
// reports the cleanup errors of owners that finished but could not be retired,
// so a caller that observes a clean shutdown knows nothing of its own is still
// running.
package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

// MemoryStorage is a simple in-memory implementation storing all debuglets in a
// priority queue sorted by their starting time.
//
// Because the WASM is also stored in memory, the memory usage of a lot of debuglets
// can be significant.
type MemoryStorage struct {
	onStartCb  scheduler.StartFunc
	onFailedCb scheduler.FailedFunc

	wakeup      chan struct{}
	mu          sync.RWMutex
	tq          *TimedQueue
	owners      map[uuid.UUID]*owner
	clock       schedulerClock
	persist     func(context.Context, scheduler.Spec) (scheduler.Spec, error)
	finalize    finalizer
	inspect     absentInspector
	admission   scheduler.Admission
	closed      bool
	stop        chan struct{}
	changed     chan struct{}
	busy        int // admissions, callbacks/finalizers, deletions and restore
	loopRunning bool
}

var _ scheduler.Scheduler = (*MemoryStorage)(nil)

// NewStorage requires both admission guards, so every core commits the
// transitions that create work under one.
func NewStorage(admission scheduler.Admission) (*MemoryStorage, error) {
	if admission.Insert == nil || admission.Start == nil {
		return nil, errors.New("scheduler admission requires insert and start guards")
	}
	return &MemoryStorage{
		admission: admission,
		wakeup:    make(chan struct{}, 1),
		tq:        NewTimedQueue(),
		owners:    make(map[uuid.UUID]*owner),
		clock:     wallClock{},
		stop:      make(chan struct{}),
		changed:   make(chan struct{}),
	}, nil
}

// Insert accepts at the append under mu. Cancellation observed immediately
// before that append rejects the job; cancellation racing an accepted append
// cannot turn it into an error or retract the accepted work.
func (m *MemoryStorage) Insert(ctx context.Context, u scheduler.Spec) error {
	return m.insert(ctx, u)
}

// A notification means recheck the authoritative queue, not dispatch one item.
func (m *MemoryStorage) notify() {
	select {
	case m.wakeup <- struct{}{}:
	default:
	}
}

// Remove uses the same owned deletion as Cancel for queued work. Active work
// returns an error; an absent admitted owner returns (false, nil).
func (m *MemoryStorage) Remove(ctx context.Context, debugletID uuid.UUID) (bool, error) {
	return m.requestCancel(ctx, debugletID, context.Canceled, true, nil)
}

func (m *MemoryStorage) RegisterOnStart(onStart scheduler.StartFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStartCb = onStart
}

func (s *MemoryStorage) RegisterFailed(cb scheduler.FailedFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onFailedCb = cb
}

func (m *MemoryStorage) StartLoop(ctx context.Context) error {
	m.mu.Lock()
	if m.onStartCb == nil {
		m.mu.Unlock()
		return errors.New("onStart is not registered")
	}
	if m.loopRunning {
		m.mu.Unlock()
		return errors.New("scheduler loop is already running")
	}
	m.loopRunning = true
	m.mu.Unlock()
	var timer schedulerTimer
	defer func() {
		stopTimer(timer)
		m.mu.Lock()
		m.loopRunning = false
		m.changedLocked()
		m.mu.Unlock()
	}()
	for {
		// Consume stale hints before checking the queue. Draining after an empty
		// check could discard the only hint for a concurrent insertion.
		select {
		case <-m.wakeup:
		default:
		}
		stopTimer(timer)
		m.mu.Lock()
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			return err
		}
		if m.closed {
			m.mu.Unlock()
			return scheduler.ErrClosed
		}
		var deadline time.Time
		hasFuture := false
		if m.tq.Len() > 0 {
			next := m.tq.Peek(0)
			if next.StartTime == nil || !next.StartTime.After(m.clock.Now()) {
				o := m.owners[next.DebugletID]
				operationCtx, cancel := context.WithCancelCause(ctx)
				var commitErr error
				commit := func() {
					if commitErr = ctx.Err(); commitErr != nil {
						return
					}
					m.tq.Pop()
					o.phase = active
					o.ctx, o.cancel = operationCtx, cancel
					o.attempt = newAttempt()
					m.busy++
				}
				if err := m.admission.Start(next.Binding, commit); err != nil {
					m.mu.Unlock()
					cancel(err)
					return err // Retain the queued owner and its canonical row.
				}
				if commitErr != nil {
					m.mu.Unlock()
					cancel(commitErr)
					return commitErr
				}
				callback := m.onStartCb
				m.mu.Unlock()
				go m.runOwner(o, callback)
				// Keep draining due entries without consuming one hint per callback.
				continue
			}
			deadline = *next.StartTime
			hasFuture = true
		}
		m.mu.Unlock()
		var timerChan <-chan time.Time
		if hasFuture {
			until := deadline.Sub(m.clock.Now())
			if timer == nil {
				timer = m.clock.NewTimer(until)
			} else {
				timer.Reset(until)
			}
			timerChan = timer.Chan()
		}
		// With an empty queue there is no active timer, only insertion/cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.stop:
			return scheduler.ErrClosed
		case <-m.wakeup:
		case <-timerChan:
		}
	}
}

// The clock is per storage instance and private; production uses Go timers, and
// a test advances exact deadlines without any timing hook reaching callers.
type schedulerClock interface {
	Now() time.Time
	NewTimer(time.Duration) schedulerTimer
}
type schedulerTimer interface {
	Chan() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}
type wallClock struct{}

func (wallClock) Now() time.Time                          { return time.Now() }
func (wallClock) NewTimer(d time.Duration) schedulerTimer { return wallTimer{time.NewTimer(d)} }

type wallTimer struct{ *time.Timer }

func (t wallTimer) Chan() <-chan time.Time { return t.C }
func stopTimer(timer schedulerTimer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.Chan():
		default:
		}
	}
}
