package resource_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
)

// The dispatcher decides the limits it hands an executor and the executor
// decides the limits it applies to its own runs. Both work from the same
// admitted floors and ceilings, in the same unit, and they have to reach the
// same numbers: a dispatcher that promises more than the executor applies
// under-uses the capacity, and one that promises less oversubscribes it.

const crossDestination = "198.51.100.7"

type crossRun struct {
	debugletID uuid.UUID
	executorID string
	floor      resource.Bitrate
	ceiling    resource.Bitrate
}

// crossAdmit charges the same workload on both sides and returns the limits
// each of them computes for it.
func crossAdmit(t *testing.T, runs []crossRun, capacity resource.Bitrate) (map[string]resource.Bitrate, map[string]app.Bitrate, map[string]app.Bitrate) {
	t.Helper()
	usage := resource.NewDestinations(capacity)
	usage.SetLimit(crossDestination, capacity)

	limiter := app.NewLimiter(zap.NewNop())
	limiter.SetExecutorCapacity(app.Bitrate(capacity))
	limiter.SetAddrCapacity(crossDestination, app.Bitrate(capacity))

	for _, run := range runs {
		if err := usage.Allocate(run.debugletID, run.executorID, []string{crossDestination}, run.floor, run.ceiling); err != nil {
			t.Fatalf("dispatcher refused the workload: %v", err)
		}
		if err := limiter.InsertDebuglet(run.debugletID, app.Bitrate(run.floor), app.Bitrate(run.ceiling), []string{crossDestination}); err != nil {
			t.Fatalf("executor refused the workload: %v", err)
		}
	}

	dispatcherLimits := make(map[string]resource.Bitrate)
	for executorID, limit := range usage.Fairshare(crossDestination) {
		dispatcherLimits[executorID] = limit
	}
	executorDestination := make(map[string]app.Bitrate)
	executorWide := make(map[string]app.Bitrate)
	for _, run := range runs {
		share, _, err := limiter.GetAddrLimit(run.debugletID, crossDestination)
		if err != nil {
			t.Fatalf("executor destination share: %v", err)
		}
		executorDestination[run.executorID] = share
		wide, _, err := limiter.GetExecLimit(run.debugletID)
		if err != nil {
			t.Fatalf("executor wide share: %v", err)
		}
		executorWide[run.executorID] = wide
	}
	return dispatcherLimits, executorDestination, executorWide
}

// crossWorkload gives every run its own executor, so the aggregate the
// dispatcher keeps per executor holds exactly one run and the two sides are
// comparable run by run.
func crossWorkload(floors, ceilings []resource.Bitrate) []crossRun {
	runs := make([]crossRun, len(floors))
	for i := range floors {
		runs[i] = crossRun{
			debugletID: uuid.New(),
			executorID: fmt.Sprintf("cross-executor-%d", i),
			floor:      floors[i],
			ceiling:    ceilings[i],
		}
	}
	return runs
}

func crossCompare(t *testing.T, what string, runs []crossRun, capacity resource.Bitrate) {
	t.Helper()
	dispatcherLimits, executorDestination, executorWide := crossAdmit(t, runs, capacity)
	if len(dispatcherLimits) != len(runs) {
		t.Fatalf("%s: dispatcher reported %d limits for %d runs", what, len(dispatcherLimits), len(runs))
	}
	var total resource.Bitrate
	for _, run := range runs {
		dispatched, ok := dispatcherLimits[run.executorID]
		if !ok {
			t.Fatalf("%s: dispatcher reported no limit for %s", what, run.executorID)
		}
		if app.Bitrate(dispatched) != executorDestination[run.executorID] {
			t.Fatalf("%s: %s destination limit is %d on the dispatcher and %d on the executor",
				what, run.executorID, int64(dispatched), int64(executorDestination[run.executorID]))
		}
		if app.Bitrate(dispatched) != executorWide[run.executorID] {
			t.Fatalf("%s: %s executor-wide limit is %d, the dispatched destination limit is %d",
				what, run.executorID, int64(executorWide[run.executorID]), int64(dispatched))
		}
		if dispatched < run.floor || dispatched > run.ceiling {
			t.Fatalf("%s: %s was given %d, outside the admitted [%d, %d]",
				what, run.executorID, int64(dispatched), int64(run.floor), int64(run.ceiling))
		}
		total += dispatched
	}
	if total > capacity {
		t.Fatalf("%s: the limits sum to %d, above the capacity %d", what, int64(total), int64(capacity))
	}
}

// TestDispatcherAndExecutorAgreeOnTheSameWorkload feeds one admitted workload
// to both calculations. The two-run example is the case that used to differ:
// the dispatcher shared what was left after the floors, the executor shared
// the whole capacity and added each floor on top.
func TestDispatcherAndExecutorAgreeOnTheSameWorkload(t *testing.T) {
	for _, tc := range []struct {
		name     string
		floors   []resource.Bitrate
		ceilings []resource.Bitrate
		capacity resource.Bitrate
	}{
		{"two runs of floor 40", []resource.Bitrate{40, 40}, []resource.Bitrate{100, 100}, 100},
		{"zero floors", []resource.Bitrate{0, 0}, []resource.Bitrate{100, 100}, 100},
		{"floors equal to ceilings", []resource.Bitrate{50, 50}, []resource.Bitrate{50, 50}, 100},
		{"asymmetric ceilings", []resource.Bitrate{10, 10}, []resource.Bitrate{20, 100}, 100},
		{"floors filling the capacity", []resource.Bitrate{60, 40}, []resource.Bitrate{100, 100}, 100},
		{"a single run", []resource.Bitrate{25}, []resource.Bitrate{100}, 100},
		{"four runs", []resource.Bitrate{10, 20, 30, 40}, []resource.Bitrate{100, 100, 100, 100}, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crossCompare(t, tc.name, crossWorkload(tc.floors, tc.ceilings), tc.capacity)
		})
	}
}

// TestDispatcherAndExecutorAgreeOnRandomizedWorkloads sweeps admitted sets the
// table does not enumerate.
func TestDispatcherAndExecutorAgreeOnRandomizedWorkloads(t *testing.T) {
	const capacity = resource.Bitrate(1000)
	for seed := int64(1); seed <= 16; seed++ {
		t.Run(fmt.Sprintf("seed/%d", seed), func(t *testing.T) {
			random := rand.New(rand.NewSource(seed))
			var floors, ceilings []resource.Bitrate
			var charged resource.Bitrate
			for range 1 + random.Intn(6) {
				floor := resource.Bitrate(random.Intn(150))
				if charged+floor > capacity {
					break
				}
				charged += floor
				floors = append(floors, floor)
				ceilings = append(ceilings, floor+resource.Bitrate(random.Intn(int(capacity))))
			}
			if len(floors) == 0 {
				return
			}
			crossCompare(t, "randomized", crossWorkload(floors, ceilings), capacity)
		})
	}
}
