package memory

import (
	"context"
	"debuglet/internal/executor/scheduler"
	"debuglet/internal/executor/transport/rpc"
	"errors"
	"sync"
	"time"
)

type MemoryStorage struct {
	onStart func(context.Context, rpc.Spec, chan<- struct{})

	wakeup chan struct{}
	mu     sync.RWMutex
	tq     *TimedQueue
}

var _ scheduler.Scheduler = (*MemoryStorage)(nil)

func NewStorage() *MemoryStorage {
	return &MemoryStorage{
		wakeup: make(chan struct{}, 32),
		tq:     NewTimedQueue(),
	}
}

func (m *MemoryStorage) Insert(u rpc.Spec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tq.Push(u)
	m.wakeup <- struct{}{}
	return nil
}

func (m *MemoryStorage) Remove(debugletID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.tq.Remove(debugletID); old == nil {
		return false
	}
	return true
}

func (m *MemoryStorage) RegisterOnStart(onStart func(context.Context, rpc.Spec, chan<- struct{})) {
	m.onStart = onStart
}

func (m *MemoryStorage) StartLoop(ctx context.Context) error {
	if m.onStart == nil {
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
				m.mu.Unlock()
				preRunLock := make(chan struct{}, 1)
				go m.onStart(ctx, *nextItem, preRunLock)
				<-preRunLock
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
