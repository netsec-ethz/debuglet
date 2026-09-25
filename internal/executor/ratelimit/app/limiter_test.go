package app

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	limiterAddrA = "203.0.113.10"
	limiterAddrB = "203.0.113.11"
)

// readDimension reads one cached dimension: the executor share under the empty
// address, a destination share otherwise.
func readDimension(l *Limiter, id uuid.UUID, dimension string) (Bitrate, bool, error) {
	if dimension == executorDimension {
		return l.GetExecLimit(id)
	}
	return l.GetAddrLimit(id, dimension)
}

// A debuglet with a zero floor and a 1000 ceiling has a residual of 1000, so a
// single member is limited by the dimension capacity alone and two equal
// members split it. That keeps every expectation below exact.
func insertLimiterRun(t *testing.T, l *Limiter, addrs ...string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := l.InsertDebuglet(id, 0, 1000, addrs); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestLimiterRecomputesAfterCapacityChange(t *testing.T) {
	l := NewLimiter(zap.NewNop())
	l.SetExecutorCapacity(800)
	l.SetAddrCapacity(limiterAddrA, 800)
	id := insertLimiterRun(t, l, limiterAddrA)

	limit, err := l.GetLimit(id, limiterAddrA)
	if err != nil {
		t.Fatal(err)
	}
	if limit.Executor != 800 || limit.Address != 800 || !limit.Updated {
		t.Fatalf("first read did not compute both dimensions: %+v", limit)
	}
	limit, err = l.GetLimit(id, limiterAddrA)
	if err != nil {
		t.Fatal(err)
	}
	if limit.Executor != 800 || limit.Address != 800 || limit.Updated {
		t.Fatalf("unchanged read recomputed or moved: %+v", limit)
	}

	// Lowering the executor capacity must be visible without any new run.
	l.SetExecutorCapacity(400)
	limit, err = l.GetLimit(id, limiterAddrA)
	if err != nil {
		t.Fatal(err)
	}
	if limit.Executor != 400 || !limit.Updated {
		t.Fatalf("executor capacity change was not applied: %+v", limit)
	}
	if limit.Address != 800 {
		t.Fatalf("executor capacity change moved the destination share: %+v", limit)
	}

	// The destination dimension behaves the same and stays independent.
	l.SetAddrCapacity(limiterAddrA, 200)
	addrLimit, updated, err := l.GetAddrLimit(id, limiterAddrA)
	if err != nil {
		t.Fatal(err)
	}
	if addrLimit != 200 || !updated {
		t.Fatalf("destination capacity change was not applied: %d updated=%v", addrLimit, updated)
	}
	execLimit, updated, err := l.GetExecLimit(id)
	if err != nil {
		t.Fatal(err)
	}
	if execLimit != 400 || updated {
		t.Fatalf("destination capacity change disturbed the executor share: %d updated=%v", execLimit, updated)
	}
}

// Each dimension keeps its own invalidation state, so reading one cached value
// can never make another dimension's outstanding invalidation look consumed.
func TestLimiterInvalidationIsNotMaskedByAnotherRead(t *testing.T) {
	orders := [][]string{
		{executorDimension, limiterAddrA, limiterAddrB},
		{executorDimension, limiterAddrB, limiterAddrA},
		{limiterAddrA, executorDimension, limiterAddrB},
		{limiterAddrA, limiterAddrB, executorDimension},
		{limiterAddrB, executorDimension, limiterAddrA},
		{limiterAddrB, limiterAddrA, executorDimension},
	}
	for _, trigger := range []string{"capacity", "membership"} {
		for i, order := range orders {
			t.Run(fmt.Sprintf("%s/%d", trigger, i), func(t *testing.T) {
				l := NewLimiter(zap.NewNop())
				l.SetExecutorCapacity(800)
				l.SetAddrCapacity(limiterAddrA, 800)
				l.SetAddrCapacity(limiterAddrB, 800)
				id := insertLimiterRun(t, l, limiterAddrA, limiterAddrB)
				for _, dimension := range order {
					value, updated, err := readDimension(l, id, dimension)
					if err != nil || value != 800 || !updated {
						t.Fatalf("priming read of %q: %d updated=%v error=%v", dimension, value, updated, err)
					}
				}

				// One trigger invalidates all three dimensions at once.
				if trigger == "capacity" {
					l.SetExecutorCapacity(400)
					l.SetAddrCapacity(limiterAddrA, 400)
					l.SetAddrCapacity(limiterAddrB, 400)
				} else {
					insertLimiterRun(t, l, limiterAddrA, limiterAddrB)
				}
				for position, dimension := range order {
					value, updated, err := readDimension(l, id, dimension)
					if err != nil {
						t.Fatal(err)
					}
					if !updated || value != 400 {
						t.Fatalf("read %d of %q lost its invalidation: %d updated=%v", position, dimension, value, updated)
					}
				}
			})
		}
	}
}

// Capacity writes, cached reads and removals run concurrently. The race
// detector owns the data-race half; the assertions own the ownership half: a
// removed run is never readable again and leaves no fairshare membership.
func TestLimiterConcurrentCapacityReadRemove(t *testing.T) {
	l := NewLimiter(zap.NewNop())
	l.SetExecutorCapacity(Gigabit)
	addrs := []string{limiterAddrA, limiterAddrB}

	stop := make(chan struct{})
	removed := make(chan uuid.UUID, 1024)
	var churn, helpers sync.WaitGroup

	helpers.Add(1)
	go func() {
		defer helpers.Done()
		for round := 0; ; round++ {
			select {
			case <-stop:
				return
			default:
			}
			l.SetExecutorCapacity(Bitrate(round%7+1) * Megabit)
			l.SetAddrCapacity(addrs[round%len(addrs)], Bitrate(round%5+1)*Megabit)
		}
	}()

	// A resurrection checker keeps reading identities that were already
	// removed, while insertions and capacity writes continue around it.
	helpers.Add(1)
	go func() {
		defer helpers.Done()
		for id := range removed {
			if _, _, err := l.GetExecLimit(id); !errors.Is(err, ErrNotRegistered) {
				t.Errorf("removed run stayed readable: %v", err)
				return
			}
			for _, addr := range addrs {
				if _, _, err := l.GetAddrLimit(id, addr); !errors.Is(err, ErrNotRegistered) && !errors.Is(err, ErrNotInPolicy) {
					t.Errorf("removed run kept a destination share: %v", err)
					return
				}
			}
		}
	}()

	for range 8 {
		churn.Add(1)
		go func() {
			defer churn.Done()
			for range 64 {
				id := uuid.New()
				if err := l.InsertDebuglet(id, 0, 1000, addrs); err != nil {
					t.Error(err)
					return
				}
				for _, addr := range addrs {
					if _, err := l.GetLimit(id, addr); err != nil {
						t.Errorf("live run lost its limit: %v", err)
						return
					}
				}
				l.RemoveDebuglet(id)
				l.RemoveDebuglet(id) // Removal stays idempotent under contention.
				if _, _, err := l.GetExecLimit(id); !errors.Is(err, ErrNotRegistered) {
					t.Errorf("removed run was resurrected: %v", err)
					return
				}
				select {
				case removed <- id:
				default:
				}
			}
		}()
	}

	churn.Wait()
	close(stop)
	close(removed)
	helpers.Wait()

	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.stores) != 0 || l.execT.Len() != 0 || len(l.addrT) != 0 {
		t.Fatalf("removed runs left state: stores=%d members=%d destinations=%d", len(l.stores), l.execT.Len(), len(l.addrT))
	}
	// Invalidation state is per dimension, not per run: a destination keeps at
	// most one counter however many runs passed through it.
	if len(l.version) > 1+len(addrs) {
		t.Fatalf("invalidation state grew with retired runs: %d dimensions", len(l.version))
	}
}

// A destination another debuglet declared is not this one's policy, and a
// cached value must not survive that destination being retired and reused.
func TestLimiterDestinationRequiresMembership(t *testing.T) {
	l := NewLimiter(zap.NewNop())
	l.SetExecutorCapacity(800)
	l.SetAddrCapacity(limiterAddrA, 800)
	l.SetAddrCapacity(limiterAddrB, 800)
	member := insertLimiterRun(t, l, limiterAddrA)
	other := insertLimiterRun(t, l, limiterAddrB)

	if _, _, err := l.GetAddrLimit(member, limiterAddrB); !errors.Is(err, ErrNotInPolicy) {
		t.Fatalf("a run read a destination it never declared: %v", err)
	}
	if _, err := l.GetLimit(member, limiterAddrB); !errors.Is(err, ErrNotInPolicy) {
		t.Fatalf("combined read crossed the policy: %v", err)
	}
	if value, _, err := l.GetAddrLimit(member, limiterAddrA); err != nil || value != 800 {
		t.Fatalf("declared destination became unreadable: %d %v", value, err)
	}

	// Retiring the last member of a destination restarts its counter. A run
	// that never joined it must still be refused rather than matching that
	// restarted counter with a stale cached value.
	l.RemoveDebuglet(other)
	rejoined := insertLimiterRun(t, l, limiterAddrB)
	if _, _, err := l.GetAddrLimit(member, limiterAddrB); !errors.Is(err, ErrNotInPolicy) {
		t.Fatalf("a retired and reused destination became readable: %v", err)
	}
	if value, updated, err := l.GetAddrLimit(rejoined, limiterAddrB); err != nil || value != 800 || !updated {
		t.Fatalf("rejoined destination: %d updated=%v error=%v", value, updated, err)
	}
}
