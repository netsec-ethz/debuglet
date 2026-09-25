// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/avl"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	defaultDestinationCapacity = Gigabit
	// executorDimension keys the executor-wide cache; every other key is a
	// destination address. Both share one namespace of invalidation counters.
	executorDimension = ""
)

var (
	ErrNotRegistered = errors.New("debuglet has not been registered")
	ErrNotInPolicy   = errors.New("address has not been registered/not in policy")
)

type Limit struct {
	Executor Bitrate
	Address  Bitrate
	Updated  bool
}

type storeValue struct {
	minimum Bitrate
	maximum Bitrate

	// Each cached value records the dimension version it was computed from, so
	// recomputing one dimension never consumes another's pending invalidation.
	lastExecLimit   Bitrate
	lastExecVersion uint64
	lastAddrLimit   map[string]Bitrate
	lastAddrVersion map[string]uint64
	tracker         *UsageTracker

	mu sync.Mutex
}

// Limiter keeps track of the bandwidth being used by individual debuglets
// as well as the maximum bandwidth any debuglet is allowed to use on a executor
// level as well as per destination.
type Limiter struct {
	// max capacity for the executor
	execCapacity Bitrate
	// max capacity for a destination address
	addrCapacity map[string]Bitrate

	// execUsed and addrUsed are the floors admitted on each dimension. A
	// floor is bandwidth its run already holds, so only what is left after
	// them is shared: sharing the whole capacity and then adding each floor
	// back hands out the reserved part of the capacity a second time, once
	// per run.
	execUsed Bitrate
	addrUsed map[string]Bitrate

	// tree for fairsharing the executors bandwidth
	execT *avl.AVL[uuid.UUID]
	// tree for fairsharing a destinations bandwidth
	addrT map[string]*avl.AVL[uuid.UUID]

	stores map[uuid.UUID]*storeValue

	mu     sync.RWMutex
	logger *zap.Logger

	// version counts the invalidations of one cached dimension: the executor
	// share under executorDimension and every destination share under its own
	// address. This enables [Limiter.GetLimit] to be cached by not having to
	// recompute a fairshare value on every call, while still recomputing it
	// after anything that can move it. A dimension is invalidated when its
	// capacity changes and when its competitors change, which happens when a
	// debuglet is added to the executor or when a debuglet with an overlapping
	// destination address is added or removed. Counters are per dimension, so a
	// cached read of one dimension can never make another dimension's
	// outstanding invalidation look consumed.
	version map[string]uint64
}

func NewLimiter(l *zap.Logger) *Limiter {
	return &Limiter{
		addrCapacity: make(map[string]Bitrate),
		addrUsed:     make(map[string]Bitrate),
		execT:        &avl.AVL[uuid.UUID]{},
		addrT:        make(map[string]*avl.AVL[uuid.UUID]),
		stores:       make(map[uuid.UUID]*storeValue),
		version:      make(map[string]uint64),
		logger:       l,
	}
}

// invalidateLocked marks one dimension as needing recomputation. Callers hold
// the write lock, so the counter cannot be observed between its two states.
func (l *Limiter) invalidateLocked(dimension string) {
	l.version[dimension]++
}

// shareableCapacity is the part of a dimension's capacity that is still free to
// be shared: what is left once the floors it already owes are subtracted. It
// never goes below zero, so a capacity that no longer covers its floors shares
// nothing out rather than taking bandwidth away from them.
func shareableCapacity(capacity, used Bitrate) Bitrate {
	if used >= capacity {
		return 0
	}
	return capacity - used
}

func (l *Limiter) SetExecutorCapacity(c Bitrate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.execCapacity == c {
		return
	}
	l.execCapacity = c
	l.invalidateLocked(executorDimension)
}
func (l *Limiter) ExecutorCapacity() Bitrate {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.execCapacity
}
func (l *Limiter) SetAddrCapacity(addr string, c Bitrate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if previous, ok := l.addrCapacity[addr]; ok && previous == c {
		return
	}
	l.addrCapacity[addr] = c
	l.invalidateLocked(addr)
}

func (l *Limiter) InsertDebuglet(ID uuid.UUID, minimum, maximum Bitrate, addrs []string) error {
	if minimum > maximum {
		return fmt.Errorf("invalid input (Got minimum (%s) > maximum (%s), Want maximum >= minimum)", minimum, maximum)
	}
	if minimum < 0 {
		return fmt.Errorf("invalid input (Got minimum (%s), Want minimum >= 0)", minimum)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	residual := int64(maximum - minimum)
	l.execT.Insert(ID, residual)
	l.execUsed += minimum

	addrLimit := make(map[string]Bitrate)
	addrVersion := make(map[string]uint64)
	l.stores[ID] = &storeValue{
		minimum:         minimum,
		maximum:         maximum,
		lastAddrLimit:   addrLimit,
		lastAddrVersion: addrVersion,
		lastExecLimit:   -1,
		tracker:         NewUsageTracker(l.logger),
	}
	l.invalidateLocked(executorDimension)
	for _, a := range addrs {
		if _, duplicate := addrLimit[a]; duplicate {
			continue // A repeated policy address is one membership, not two.
		}
		addrLimit[a] = -1
		if _, ok := l.addrT[a]; !ok {
			l.addrT[a] = &avl.AVL[uuid.UUID]{}
		}
		l.addrT[a].Insert(ID, residual)
		l.addrUsed[a] += minimum
		l.invalidateLocked(a)
	}
	return nil
}

func (l *Limiter) RemoveDebuglet(ID uuid.UUID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	store, ok := l.stores[ID]
	if !ok {
		return // Removal is idempotent and never invalidates a live dimension.
	}
	l.execT.Delete(ID)
	l.execUsed -= store.minimum
	l.invalidateLocked(executorDimension)

	for a := range store.lastAddrLimit {
		aTree, exists := l.addrT[a]
		if !exists {
			continue
		}
		aTree.Delete(ID)
		l.addrUsed[a] -= store.minimum
		if aTree.Len() == 0 {
			// The removed debuglet was the last member, so no cached value can
			// still refer to this dimension and its counter can start over.
			delete(l.addrT, a)
			delete(l.addrUsed, a)
			delete(l.version, a)
		} else {
			l.invalidateLocked(a)
		}
	}
	delete(l.stores, ID)
}

func (l *Limiter) GetExecLimit(ID uuid.UUID) (Bitrate, bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	store, ok := l.stores[ID]
	if !ok {
		return 0, false, ErrNotRegistered
	}
	version := l.version[executorDimension]
	shareable := shareableCapacity(l.execCapacity, l.execUsed)

	store.mu.Lock()
	defer store.mu.Unlock()

	execLimit := store.lastExecLimit
	if execLimit == -1 || store.lastExecVersion != version {
		maxExecFairshare := Bitrate(l.execT.Fairshare(int64(shareable)))
		execLimit = min(store.maximum, store.minimum+maxExecFairshare)
		store.lastExecVersion = version
		store.lastExecLimit = execLimit
		return execLimit, true, nil
	}

	return execLimit, false, nil
}

func (l *Limiter) GetAddrLimit(ID uuid.UUID, addr string) (Bitrate, bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	store, ok := l.stores[ID]
	if !ok {
		return 0, false, ErrNotRegistered
	}

	tree, ok := l.addrT[addr]
	if !ok {
		return 0, false, ErrNotInPolicy
	}
	// A destination another debuglet declared is still not this one's policy,
	// and its cached value must not survive that destination being retired.
	if tree.Get(ID) == nil {
		return 0, false, ErrNotInPolicy
	}
	addrCap, ok := l.addrCapacity[addr]
	if !ok {
		addrCap = defaultDestinationCapacity
	}
	version := l.version[addr]
	shareable := shareableCapacity(addrCap, l.addrUsed[addr])

	store.mu.Lock()
	defer store.mu.Unlock()

	addrLimit, cached := store.lastAddrLimit[addr]
	if !cached || addrLimit == -1 || store.lastAddrVersion[addr] != version {
		maxAddrFairshare := Bitrate(tree.Fairshare(int64(shareable)))
		addrLimit = min(store.maximum, store.minimum+maxAddrFairshare)
		store.lastAddrVersion[addr] = version
		store.lastAddrLimit[addr] = addrLimit
		return addrLimit, true, nil
	}

	return addrLimit, false, nil
}

func (l *Limiter) GetLimit(ID uuid.UUID, addr string) (Limit, error) {
	execLimit, execUpdated, err := l.GetExecLimit(ID)
	if err != nil {
		return Limit{}, err
	}

	addrLimit, addrUpdated, err := l.GetAddrLimit(ID, addr)
	if err != nil {
		return Limit{}, err
	}

	updated := execUpdated || addrUpdated

	return Limit{Executor: execLimit, Address: addrLimit, Updated: updated}, nil
}

func (l *Limiter) Wait(ctx context.Context, direction TransferDirection, ID uuid.UUID, addr string, size Bitrate) error {
	l.mu.RLock()
	store, ok := l.stores[ID]
	if !ok {
		l.mu.RUnlock()
		return fmt.Errorf("ID '%s' has not been inserted", ID)
	}
	tracker := store.tracker
	l.mu.RUnlock()

	limit, err := l.GetLimit(ID, addr)
	if err != nil {
		return fmt.Errorf("failed to wait: %w", err)
	}

	// Cache freshness is shared with packet-counter publication; accounting
	// must receive the current limits even when another reader computed them.
	tracker.Upsert(addr, UsageLimits{
		ExecutorRatelimit:    limit.Executor,
		ExecutorBurst:        limit.Executor,
		DestinationRatelimit: limit.Address,
		DestinationBurst:     limit.Address,
	})

	return tracker.Wait(ctx, direction, addr, size)
}
