package app

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// A floor is bandwidth its run already holds. Sharing therefore starts from
// what is left once every admitted floor is subtracted: sharing the whole
// capacity and adding each floor back afterwards hands the reserved part out
// once per run, and the runs together then exceed the capacity they share.

const (
	fairAddrA = "203.0.113.20"
	fairAddrB = "203.0.113.21"
	fairAddrC = "203.0.113.22"
)

type fairRun struct {
	id      uuid.UUID
	floor   Bitrate
	ceiling Bitrate
	addrs   []string
}

func fairInsert(t *testing.T, l *Limiter, floor, ceiling Bitrate, addrs ...string) fairRun {
	t.Helper()
	run := fairRun{id: uuid.New(), floor: floor, ceiling: ceiling, addrs: addrs}
	if err := l.InsertDebuglet(run.id, floor, ceiling, addrs); err != nil {
		t.Fatalf("insert floor=%d ceiling=%d: %v", int64(floor), int64(ceiling), err)
	}
	return run
}

// fairCheck states the whole contract of a limiter over one admitted set of
// runs: every run keeps its floor, no run passes its ceiling, and the runs
// sharing a dimension never add up to more than its capacity.
func fairCheck(t *testing.T, what string, l *Limiter, runs []fairRun, execCapacity, addrCapacity Bitrate) {
	t.Helper()
	var execSum, execFloors Bitrate
	addrSums := make(map[string]Bitrate)
	addrFloors := make(map[string]Bitrate)

	for _, run := range runs {
		limit, _, err := l.GetExecLimit(run.id)
		if err != nil {
			t.Fatalf("%s: executor share of an admitted run: %v", what, err)
		}
		if limit < run.floor || limit > run.ceiling {
			t.Fatalf("%s: executor share %d outside the admitted [%d, %d]",
				what, int64(limit), int64(run.floor), int64(run.ceiling))
		}
		execSum += limit
		execFloors += run.floor

		for _, addr := range slices.Compact(slices.Sorted(slices.Values(run.addrs))) {
			share, _, err := l.GetAddrLimit(run.id, addr)
			if err != nil {
				t.Fatalf("%s: share of %s for an admitted run: %v", what, addr, err)
			}
			if share < run.floor || share > run.ceiling {
				t.Fatalf("%s: share of %s is %d, outside the admitted [%d, %d]",
					what, addr, int64(share), int64(run.floor), int64(run.ceiling))
			}
			addrSums[addr] += share
			addrFloors[addr] += run.floor
		}
	}

	// The capacity bounds the sum exactly while the floors themselves fit. An
	// oversubscribed dimension is an admission failure, not a sharing one, and
	// the floors stay satisfied there.
	if execFloors <= execCapacity && execSum > execCapacity {
		t.Fatalf("%s: executor shares sum to %d, above the capacity %d", what, int64(execSum), int64(execCapacity))
	}
	for addr, sum := range addrSums {
		if addrFloors[addr] <= addrCapacity && sum > addrCapacity {
			t.Fatalf("%s: shares of %s sum to %d, above the capacity %d", what, addr, int64(sum), int64(addrCapacity))
		}
	}
}

// TestLimiterSharesOnlyWhatFloorsLeave is the example from the report: two
// runs with a floor of 40 and a ceiling of 100 on a capacity of 100. Sharing
// the full capacity gave each of them 90.
func TestLimiterSharesOnlyWhatFloorsLeave(t *testing.T) {
	l := NewLimiter(zap.NewNop())
	l.SetExecutorCapacity(100)
	l.SetAddrCapacity(fairAddrA, 100)
	first := fairInsert(t, l, 40, 100, fairAddrA)
	second := fairInsert(t, l, 40, 100, fairAddrA)

	for _, run := range []fairRun{first, second} {
		limit, err := l.GetLimit(run.id, fairAddrA)
		if err != nil {
			t.Fatal(err)
		}
		if limit.Executor != 50 || limit.Address != 50 {
			t.Fatalf("share = %+v, want 50 on both dimensions: 40 reserved plus half of the 20 that are left", limit)
		}
	}
	fairCheck(t, "two runs of floor 40", l, []fairRun{first, second}, 100, 100)

	// One run alone may use everything its ceiling allows again.
	l.RemoveDebuglet(second.id)
	limit, err := l.GetLimit(first.id, fairAddrA)
	if err != nil {
		t.Fatal(err)
	}
	if limit.Executor != 100 || limit.Address != 100 {
		t.Fatalf("share after removal = %+v, want the whole capacity", limit)
	}
	fairCheck(t, "one remaining run", l, []fairRun{first}, 100, 100)
}

// TestLimiterFairshareShapes covers the shapes a sharing rule has to get right:
// no floors at all, floors equal to their ceilings, ceilings that differ, and
// destinations shared by some runs and not by others.
func TestLimiterFairshareShapes(t *testing.T) {
	const capacity = Bitrate(100)
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, l *Limiter) []fairRun
	}{
		{"zero floors", func(t *testing.T, l *Limiter) []fairRun {
			return []fairRun{
				fairInsert(t, l, 0, 100, fairAddrA),
				fairInsert(t, l, 0, 100, fairAddrA),
			}
		}},
		{"floors equal to ceilings", func(t *testing.T, l *Limiter) []fairRun {
			return []fairRun{
				fairInsert(t, l, 50, 50, fairAddrA),
				fairInsert(t, l, 50, 50, fairAddrA),
			}
		}},
		{"asymmetric ceilings", func(t *testing.T, l *Limiter) []fairRun {
			return []fairRun{
				fairInsert(t, l, 10, 20, fairAddrA),
				fairInsert(t, l, 10, 100, fairAddrA),
			}
		}},
		{"one floor and one ceiling", func(t *testing.T, l *Limiter) []fairRun {
			return []fairRun{
				fairInsert(t, l, 90, 100, fairAddrA),
				fairInsert(t, l, 0, 100, fairAddrA),
			}
		}},
		{"floors filling the capacity", func(t *testing.T, l *Limiter) []fairRun {
			return []fairRun{
				fairInsert(t, l, 60, 100, fairAddrA),
				fairInsert(t, l, 40, 100, fairAddrA),
			}
		}},
		{"overlapping destinations", func(t *testing.T, l *Limiter) []fairRun {
			return []fairRun{
				fairInsert(t, l, 20, 100, fairAddrA, fairAddrB),
				fairInsert(t, l, 20, 100, fairAddrB, fairAddrC),
				fairInsert(t, l, 20, 100, fairAddrC),
			}
		}},
		{"a repeated destination is one membership", func(t *testing.T, l *Limiter) []fairRun {
			return []fairRun{
				fairInsert(t, l, 40, 100, fairAddrA, fairAddrA),
				fairInsert(t, l, 40, 100, fairAddrA),
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := NewLimiter(zap.NewNop())
			l.SetExecutorCapacity(capacity)
			for _, addr := range []string{fairAddrA, fairAddrB, fairAddrC} {
				l.SetAddrCapacity(addr, capacity)
			}
			runs := tc.build(t, l)
			fairCheck(t, tc.name, l, runs, capacity, capacity)

			// Removing a member and admitting another one leaves the same
			// contract standing, from the recomputed state rather than the
			// cached one.
			l.RemoveDebuglet(runs[0].id)
			fairCheck(t, tc.name+" after a removal", l, runs[1:], capacity, capacity)
			admitted := append(slices.Clone(runs[1:]), fairInsert(t, l, 0, capacity, fairAddrA, fairAddrB, fairAddrC))
			fairCheck(t, tc.name+" after an insertion", l, admitted, capacity, capacity)
		})
	}
}

// TestLimiterFairshareRandomizedWorkloads sweeps admitted sets the shapes above
// do not enumerate. Floors are drawn so that they fit the capacity, which is
// what admission guarantees, and every intermediate state is checked.
func TestLimiterFairshareRandomizedWorkloads(t *testing.T) {
	const capacity = Bitrate(1000)
	addrs := []string{fairAddrA, fairAddrB, fairAddrC}
	for seed := int64(1); seed <= 16; seed++ {
		t.Run(fmt.Sprintf("seed/%d", seed), func(t *testing.T) {
			random := rand.New(rand.NewSource(seed))
			l := NewLimiter(zap.NewNop())
			l.SetExecutorCapacity(capacity)
			for _, addr := range addrs {
				l.SetAddrCapacity(addr, capacity)
			}

			var runs []fairRun
			var floors Bitrate
			for range 1 + random.Intn(6) {
				floor := Bitrate(random.Intn(120))
				if floors+floor > capacity {
					break
				}
				floors += floor
				ceiling := floor + Bitrate(random.Intn(int(capacity)))
				var declared []string
				for _, addr := range addrs {
					if random.Intn(2) == 0 {
						declared = append(declared, addr)
					}
				}
				if declared == nil {
					declared = []string{addrs[random.Intn(len(addrs))]}
				}
				runs = append(runs, fairInsert(t, l, floor, ceiling, declared...))
				fairCheck(t, "after an insertion", l, runs, capacity, capacity)
			}

			for len(runs) > 0 {
				at := random.Intn(len(runs))
				l.RemoveDebuglet(runs[at].id)
				runs = slices.Delete(slices.Clone(runs), at, at+1)
				fairCheck(t, "after a removal", l, runs, capacity, capacity)
			}
		})
	}
}
