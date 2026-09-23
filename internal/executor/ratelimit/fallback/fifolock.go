// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package fallback

import (
	"net"
	"os"
	"sync"
	"time"
)

type FIFOLock struct {
	mu      sync.Mutex
	locked  bool
	waiters []*fifoWaiter
}

type fifoWaiter struct{ ready chan struct{} }

func NewFIFOLock() *FIFOLock {
	return &FIFOLock{}
}

func (l *FIFOLock) Lock() {
	_ = l.LockUntil(nil, func() (time.Time, <-chan struct{}) { return time.Time{}, nil })
}

func (l *FIFOLock) LockUntil(closed <-chan struct{}, deadlineState func() (time.Time, <-chan struct{})) error {
	// Closure takes precedence over an expired deadline so that every
	// operation on a closed connection reports net.ErrClosed.
	select {
	case <-closed:
		return net.ErrClosed
	default:
	}
	deadline, changed := deadlineState()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}

	l.mu.Lock()
	if !l.locked {
		l.locked = true
		l.mu.Unlock()
		return nil
	}

	w := &fifoWaiter{ready: make(chan struct{})}
	l.waiters = append(l.waiters, w)
	l.mu.Unlock()

	for {
		var deadlineC <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			deadlineC = timer.C
		}
		select {
		case <-w.ready:
			stopTimer(timer)
			select {
			case <-closed:
				l.Unlock()
				return net.ErrClosed
			default:
			}
			deadline, _ = deadlineState()
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				l.Unlock()
				return os.ErrDeadlineExceeded
			}
			return nil
		case <-closed:
			stopTimer(timer)
			l.cancel(w)
			return net.ErrClosed
		case <-deadlineC:
			deadline, changed = deadlineState()
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				l.cancel(w)
				return os.ErrDeadlineExceeded
			}
		case <-changed:
			stopTimer(timer)
			deadline, changed = deadlineState()
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				l.cancel(w)
				return os.ErrDeadlineExceeded
			}
		}
	}
}

func stopTimer(timer *time.Timer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (l *FIFOLock) cancel(w *fifoWaiter) {
	l.mu.Lock()
	for i, queued := range l.waiters {
		if queued == w {
			l.waiters = append(l.waiters[:i], l.waiters[i+1:]...)
			l.mu.Unlock()
			return
		}
	}
	l.mu.Unlock()

	// Unlock may have transferred ownership while cancellation was selected.
	// In that case the canceled caller owns the lock and must pass it on.
	l.Unlock()
}

func (l *FIFOLock) Unlock() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.waiters) > 0 {
		next := l.waiters[0]
		l.waiters = l.waiters[1:]
		close(next.ready)
	} else {
		l.locked = false
	}
}
