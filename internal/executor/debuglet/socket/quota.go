// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"errors"
	"fmt"
	"math"
	"sync"
)

var ErrQuota = errors.New("guest socket quota exceeded")

const (
	DefaultLiveSockets     = 64
	DefaultListeners       = 3
	DefaultSocketAttempts  = 4096
	DefaultNodeDescriptors = 1024
)

// Limits bound a run's live connections, listeners and lifetime connection
// attempts. Failed dial/accept attempts count once admitted; closing a socket
// returns live capacity but never resets the lifetime budget or its handle.
type Limits struct {
	LiveSockets    int
	Listeners      int
	SocketAttempts int
}

func DefaultLimits() Limits {
	return Limits{DefaultLiveSockets, DefaultListeners, DefaultSocketAttempts}
}

// DescriptorBudget is shared by every run and control session on one node.
// It counts guest socket reservations, not the process's complete descriptor
// table. Control transports do not acquire from this budget.
type DescriptorBudget struct {
	mu    sync.Mutex
	limit int
	used  int
}

func NewDescriptorBudget(limit int) *DescriptorBudget {
	if limit <= 0 {
		panic("socket descriptor budget must be positive")
	}
	return &DescriptorBudget{limit: limit}
}

// Budget belongs to one run. Limits are fixed at construction.
type Budget struct {
	mu                        sync.Mutex
	limits                    Limits
	node                      *DescriptorBudget
	live, listeners, attempts int
}

func NewBudget(limits Limits, node *DescriptorBudget) *Budget {
	if limits.LiveSockets <= 0 || limits.Listeners <= 0 || limits.SocketAttempts <= 0 || limits.SocketAttempts > math.MaxInt32 || node == nil {
		panic("socket budget requires positive finite limits and a node budget")
	}
	return &Budget{limits: limits, node: node}
}

// Reservation owns capacity from before an external operation starts until
// its resource has been closed or creation has failed. Release is idempotent.
type Reservation struct {
	budget      *Budget
	descriptors int
	listener    bool
	once        sync.Once
}

func (b *Budget) ReserveSocket(descriptors int) (*Reservation, error) {
	return b.reserve(false, descriptors)
}

func (b *Budget) ReserveListener() (*Reservation, error) {
	return b.reserve(true, 1)
}

func (b *Budget) reserve(listener bool, descriptors int) (*Reservation, error) {
	if descriptors <= 0 {
		return nil, fmt.Errorf("%w: invalid descriptor reservation", ErrQuota)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if listener {
		if b.listeners >= b.limits.Listeners {
			return nil, fmt.Errorf("%w: per-run listener limit", ErrQuota)
		}
	} else {
		if b.live >= b.limits.LiveSockets {
			return nil, fmt.Errorf("%w: per-run live socket limit", ErrQuota)
		}
		if b.attempts >= b.limits.SocketAttempts {
			return nil, fmt.Errorf("%w: per-run socket attempt limit", ErrQuota)
		}
	}
	b.node.mu.Lock()
	defer b.node.mu.Unlock()
	if descriptors > b.node.limit-b.node.used {
		return nil, fmt.Errorf("%w: node guest descriptor limit", ErrQuota)
	}
	b.node.used += descriptors
	if listener {
		b.listeners++
	} else {
		b.live++
		b.attempts++
	}
	return &Reservation{budget: b, descriptors: descriptors, listener: listener}, nil
}

func (r *Reservation) Release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		b := r.budget
		b.mu.Lock()
		defer b.mu.Unlock()
		if r.listener {
			b.listeners--
		} else {
			b.live--
		}
		b.node.mu.Lock()
		b.node.used -= r.descriptors
		b.node.mu.Unlock()
	})
}
