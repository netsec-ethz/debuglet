package memory

import (
	"container/heap"
	"context"
	"debuglet/internal/executor/db"
	"debuglet/internal/executor/transport"
	"errors"
	"sync"
	"time"
)

type MemoryStorage struct {
	onStartCb func(context.Context, transport.Upload) error
	onErrorCb func(string, error)

	wakeup chan struct{}
	mu     sync.RWMutex
	prioQ  *TimedQueue
}

var _ db.Storage = (*MemoryStorage)(nil)

func NewStorage() *MemoryStorage {
	tq := &TimedQueue{}
	heap.Init(tq)
	return &MemoryStorage{
		wakeup: make(chan struct{}),
		prioQ:  tq,
	}
}

func (m *MemoryStorage) Insert(u transport.Upload) error {
	m.mu.Lock()
	heap.Push(m.prioQ, u)
	m.mu.Unlock()
	m.wakeup <- struct{}{}
	return nil
}

func (m *MemoryStorage) RegisterOnStart(onStart func(context.Context, transport.Upload) error) {
	m.onStartCb = onStart
}

func (m *MemoryStorage) onStart(ctx context.Context, u transport.Upload) error {
	if m.onStartCb == nil {
		return errors.New("onStart not registered")
	}
	return m.onStartCb(ctx, u)
}

func (m *MemoryStorage) RegisterOnError(onErr func(string, error)) {
	m.onErrorCb = onErr
}

func (m *MemoryStorage) onError(debugletID string, err error) {
	if m.onStartCb == nil {
		return
	}
	m.onErrorCb(debugletID, err)
}

func (m *MemoryStorage) StartLoop(ctx context.Context) error {
	var timerChan <-chan time.Time
	var timer *time.Timer

	for {
		m.mu.Lock()

		if m.prioQ.Len() > 0 {
			nextItem := (*m.prioQ)[0]
			if nextItem.StartTime == nil || time.Now().After(*nextItem.StartTime) {
				heap.Pop(m.prioQ)
				m.mu.Unlock()
				go func() {
					if err := m.onStart(ctx, *nextItem); err != nil {
						m.onError(nextItem.DebugletID, err)
					}
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
