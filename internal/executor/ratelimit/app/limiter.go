package app

import (
	"context"
	"debuglet/internal/executor/ratelimit/app/avl"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	defaultDestinationCapacity = Gigabit
)

type Limit struct {
	Executor Bitrate
	Address  Bitrate
	Updated  bool
}

type storeValue struct {
	minimum Bitrate
	maximum Bitrate

	lastExecLimit Bitrate
	lastAddrLimit map[string]Bitrate
	tracker       *UsageTracker

	lastUpdate time.Time

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

	// tree for fairsharing the executors bandwidth
	execT *avl.AVL[string]
	// tree for fairsharing a destinations bandwidth
	addrT map[string]*avl.AVL[string]

	stores map[string]*storeValue

	mu     sync.RWMutex
	logger *zap.Logger

	// dirty keeps track of when destinations (and the executor with a key of "")
	// have last been modified. This enables [Limiter.GetLimit] to be cached by not
	// having to recompute the fairshare value every time it's called, but instead only
	// if either a new debuglet has been added to the executor (requiring the executor
	// fairshare to be recomputed) or a debuglet has an overlap of destination addresses
	// with another, requiring those destination fairshares to be updated.
	dirty map[string]time.Time
}

func NewLimiter(l *zap.Logger) *Limiter {
	return &Limiter{
		addrCapacity: make(map[string]Bitrate),
		execT:        &avl.AVL[string]{},
		addrT:        make(map[string]*avl.AVL[string]),
		stores:       make(map[string]*storeValue),
		dirty:        make(map[string]time.Time),
		logger:       l,
	}
}

func (l *Limiter) SetExecutorCapacity(c Bitrate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.execCapacity = c
}
func (l *Limiter) SetAddrCapacity(addr string, c Bitrate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addrCapacity[addr] = c
}

func (l *Limiter) InsertDebuglet(ID string, minimum, maximum Bitrate, addrs []string) error {
	if minimum > maximum {
		return fmt.Errorf("invalid input (Got minimum (%s) > maximum (%s), Want maximum >= minimum)", minimum, maximum)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	residual := int64(maximum - minimum)
	l.execT.Insert(ID, residual)

	addrLimit := make(map[string]Bitrate)
	l.stores[ID] = &storeValue{
		minimum:       minimum,
		maximum:       maximum,
		lastAddrLimit: addrLimit,
		lastExecLimit: -1,
		tracker:       NewUsageTracker(l.logger),
	}
	l.dirty[""] = time.Now()
	for _, a := range addrs {
		addrLimit[a] = -1
		if _, ok := l.addrT[a]; !ok {
			l.addrT[a] = &avl.AVL[string]{}
		}
		l.addrT[a].Insert(ID, residual)
		l.dirty[a] = time.Now()
	}
	return nil
}

func (l *Limiter) RemoveDebuglet(ID string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.execT.Delete(ID)
	if store, ok := l.stores[ID]; ok {
		for a, _ := range store.lastAddrLimit {
			if aTree, exists := l.addrT[a]; exists {
				aTree.Delete(ID)
				if aTree.Len() == 0 {
					delete(l.addrT, a)
					delete(l.dirty, a)
				} else {
					l.dirty[a] = time.Now()
				}
			}
		}
	}
	delete(l.stores, ID)
}

func (l *Limiter) GetLimit(ID string, addr string) (Limit, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	store, ok := l.stores[ID]
	if !ok {
		return Limit{}, fmt.Errorf("debuglet ID '%s' has not been registered", ID)
	}

	if _, ok := l.addrT[addr]; !ok {
		return Limit{}, fmt.Errorf("address '%s' has not been registered/not in policy", addr)
	}
	addrCap, ok := l.addrCapacity[addr]
	if !ok {
		addrCap = defaultDestinationCapacity
	}

	updated := false
	execLimit := store.lastExecLimit
	addrLimit := store.lastAddrLimit[addr]

	if execLimit == -1 || l.dirty[""].After(store.lastUpdate) {
		maxExecFairshare := Bitrate(l.execT.Fairshare(int64(l.execCapacity)))
		execLimit = min(store.maximum, store.minimum+maxExecFairshare)
		updated = true
	}

	if addrLimit == -1 || l.dirty[addr].After(store.lastUpdate) {
		maxAddrFairshare := Bitrate(l.addrT[addr].Fairshare(int64(addrCap)))
		addrLimit = min(store.maximum, store.minimum+maxAddrFairshare)
		updated = true
	}

	if updated {
		store.mu.Lock()
		store.lastUpdate = time.Now()
		store.lastExecLimit = execLimit
		store.lastAddrLimit[addr] = addrLimit
		store.mu.Unlock()
	}

	return Limit{Executor: execLimit, Address: addrLimit, Updated: updated}, nil
}

func (l *Limiter) Wait(ctx context.Context, direction TransferDirection, ID, addr string, size Bitrate) error {
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

	if limit.Updated {
		limits := UsageLimits{
			ExecutorRatelimit:    limit.Executor,
			ExecutorBurst:        limit.Executor,
			DestinationRatelimit: limit.Address,
			DestinationBurst:     limit.Address,
		}
		tracker.Upsert(addr, limits)
	}

	return tracker.Wait(ctx, direction, addr, size)
}
