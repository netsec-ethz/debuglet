package memory

import (
	"context"
	"debuglet/internal/executor/scheduler"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStorage is a simple in-memory implementation storing all debuglets in a
// priority queue sorted by their starting time.
//
// Because the WASM is also stored in memory, the memory usage of a lot of debuglets
// can be significant.
type MemoryStorage struct {
	onStartCb  func(context.Context, scheduler.Spec)
	onFailedCb func(context.Context, scheduler.Spec, error)

	wakeup   chan struct{}
	mu       sync.RWMutex
	tq       *TimedQueue
	inflight map[uuid.UUID]struct{} // popped from queue, waiting for executor to take ownership
}

var _ scheduler.Scheduler = (*MemoryStorage)(nil)

func NewStorage() *MemoryStorage {
	return &MemoryStorage{
		wakeup:   make(chan struct{}, 32),
		tq:       NewTimedQueue(),
		inflight: make(map[uuid.UUID]struct{}),
	}
}

func (m *MemoryStorage) Insert(ctx context.Context, u scheduler.Spec) error {
	m.mu.Lock()
	m.tq.Push(u)
	m.mu.Unlock()

	m.wakeup <- struct{}{}
	return nil
}

func (m *MemoryStorage) Remove(ctx context.Context, debugletID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Already handed to the executor — treat as "already started".
	if _, ok := m.inflight[debugletID]; ok {
		return false, fmt.Errorf("debuglet %s is already started", debugletID)
	}
	return m.tq.Remove(debugletID) != nil, nil
}

func (m *MemoryStorage) RegisterOnStart(onStart func(context.Context, scheduler.Spec)) {
	m.onStartCb = onStart
}

func (s *MemoryStorage) RegisterFailed(cb func(context.Context, scheduler.Spec, error)) {
	s.onFailedCb = cb
}

func (m *MemoryStorage) StartLoop(ctx context.Context) error {
	if m.onStartCb == nil {
		return errors.New("onStart is not registered")
	}

	var timerChan <-chan time.Time
	var timer *time.Timer

	for {
		m.mu.Lock()

		if m.tq.Len() > 0 {
			nextItem := m.tq.Peek(0)
			if nextItem.StartTime == nil || time.Now().After(*nextItem.StartTime) {
				m.tq.Pop()
				m.inflight[nextItem.DebugletID] = struct{}{}
				m.mu.Unlock()
				go func() {
					m.onStartCb(ctx, *nextItem)
					m.mu.Lock()
					delete(m.inflight, nextItem.DebugletID)
					m.mu.Unlock()
				}()
			} else {
				// sleep until next debuglet should start
				m.mu.Unlock()
				until := time.Until(*nextItem.StartTime)
				timer = time.NewTimer(until)
				timerChan = timer.C
			}
		} else {
			// no debuglets. sleep until new debuglet is uploaded
			m.mu.Unlock()
			timerChan = nil
			timer = nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.wakeup:
		case <-timerChan:
		}
	}
}
