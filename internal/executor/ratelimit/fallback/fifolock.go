// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package fallback

import "sync"

type FIFOLock struct {
	mu      sync.Mutex
	locked  bool
	waiters []chan struct{}
}

func NewFIFOLock() *FIFOLock {
	return &FIFOLock{}
}

func (l *FIFOLock) Lock() {
	l.mu.Lock()
	if !l.locked {
		l.locked = true
		l.mu.Unlock()
		return
	}

	ch := make(chan struct{})
	l.waiters = append(l.waiters, ch)
	l.mu.Unlock()

	<-ch
}

func (l *FIFOLock) Unlock() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.waiters) > 0 {
		next := l.waiters[0]
		l.waiters = l.waiters[1:]
		close(next)
	} else {
		l.locked = false
	}
}
