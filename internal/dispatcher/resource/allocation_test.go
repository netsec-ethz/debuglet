package resource_test

import (
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
)

// TestInsertRecordsOneDecisionPerRun states the idempotence of an allocation:
// the decision is recorded once per run and destination, repeating it changes
// nothing, and the single release returns exactly what was charged.
func TestInsertRecordsOneDecisionPerRun(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	if err := d.Insert(testDebugletID, dest, "e1", 10, 40); err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	charged := d.Snapshot()
	for i := range 3 {
		if err := d.Insert(testDebugletID, dest, "e1", 10, 40); err != nil {
			t.Fatalf("repeat %d of the same allocation: %v", i, err)
		}
		if got := d.Snapshot(); got != charged {
			t.Fatalf("repeat %d charged again:\nfirst:\n%s\nrepeated:\n%s", i, charged, got)
		}
	}
	if used, count := d.Used(dest), d.ActiveAllocations(); used != 10 || count != 1 {
		t.Fatalf("repeated allocation left used=%s over %d recorded decisions, want 10 over 1", used, count)
	}
	d.Remove(testDebugletID, dest)
	if got := d.Snapshot(); got != "" {
		t.Fatalf("one release did not return the totals of a repeated allocation:\n%s", got)
	}
}

// TestInsertRejectsChangedPolicy states that the recorded decision is
// immutable: neither a changed floor, ceiling nor executor can replace it, and
// a rejected request leaves every store and another run's capacity untouched.
func TestInsertRejectsChangedPolicy(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	if err := d.Insert(testDebugletID, dest, "e1", 10, 40); err != nil {
		t.Fatalf("allocate first run: %v", err)
	}
	if err := d.Insert(testDebugletID2, dest, "e2", 20, 60); err != nil {
		t.Fatalf("allocate second run: %v", err)
	}
	before := d.Snapshot()
	sibling := maps.Collect(d.Fairshare(dest))
	for _, tc := range []struct {
		name       string
		executorID string
		minimum    resource.Bitrate
		maximum    resource.Bitrate
	}{
		{"floor", "e1", 70, 40},
		{"raised floor", "e1", 30, 40},
		{"ceiling", "e1", 10, 90},
		{"executor", "e3", 10, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := d.Insert(testDebugletID, dest, tc.executorID, tc.minimum, tc.maximum)
			if err == nil {
				t.Fatal("changed policy was admitted")
			}
			if !errors.Is(err, resource.ErrPolicyConflict) && !errors.Is(err, resource.ErrMinGreater) {
				t.Fatalf("changed policy rejected with %v", err)
			}
			if got := d.Snapshot(); got != before {
				t.Fatalf("changed policy altered the stores:\nbefore:\n%s\nafter:\n%s", before, got)
			}
			if got := maps.Collect(d.Fairshare(dest)); !maps.Equal(got, sibling) {
				t.Fatalf("changed policy altered capacity, fairshare %v, want %v", got, sibling)
			}
		})
	}
	d.Remove(testDebugletID, dest)
	d.Remove(testDebugletID2, dest)
	if got := d.Snapshot(); got != "" {
		t.Fatalf("releases after rejected changes left residue:\n%s", got)
	}
}

// TestRemoveIgnoresUnrecordedAllocations states that a release only ever
// subtracts a decision that was recorded, so a duplicate or unknown release
// cannot return capacity twice.
func TestRemoveIgnoresUnrecordedAllocations(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	if err := d.Insert(testDebugletID, dest, "e1", 10, 40); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	charged := d.Snapshot()
	d.Remove(testDebugletID2, dest)
	d.Remove(testDebugletID, "128.0.0.1")
	if got := d.Snapshot(); got != charged {
		t.Fatalf("unrecorded release changed the stores:\nbefore:\n%s\nafter:\n%s", charged, got)
	}
	d.Remove(testDebugletID, dest)
	released := d.Snapshot()
	d.Remove(testDebugletID, dest)
	if got := d.Snapshot(); got != released || got != "" {
		t.Fatalf("duplicate release returned capacity twice:\n%s", got)
	}
}

// TestAllocateChargesRepeatedDestinationsOnce states that a repeated
// destination is one destination of the run: it is charged once and released
// by one removal.
func TestAllocateChargesRepeatedDestinationsOnce(t *testing.T) {
	dest := "128.0.0.0"
	repeated := resource.NewDestinations(100)
	if err := repeated.Allocate(testDebugletID, "e1", []string{dest, dest, dest}, 10, 40); err != nil {
		t.Fatalf("allocate repeated destinations: %v", err)
	}
	once := resource.NewDestinations(100)
	if err := once.Allocate(testDebugletID, "e1", []string{dest}, 10, 40); err != nil {
		t.Fatalf("allocate destination: %v", err)
	}
	if got, want := repeated.Snapshot(), once.Snapshot(); got != want {
		t.Fatalf("repeated destination charged more than once:\ngot:\n%s\nwant:\n%s", got, want)
	}
	repeated.Remove(testDebugletID, dest)
	if got := repeated.Snapshot(); got != "" {
		t.Fatalf("one release did not return a repeated destination:\n%s", got)
	}
}

// TestAllocateRollsBackAPartialFailure states that a destination that cannot
// be charged undoes the destinations this call already charged, so the
// allocation either holds for the whole run or leaves nothing behind.
func TestAllocateRollsBackAPartialFailure(t *testing.T) {
	d := resource.NewDestinations(100)
	first, blocked := "128.0.0.0", "128.0.0.1"
	d.SetLimit(blocked, 5)
	// A sibling run holds capacity on the destination that is charged first.
	if err := d.Insert(testDebugletID2, first, "e2", 10, 40); err != nil {
		t.Fatalf("allocate sibling run: %v", err)
	}
	before := d.Snapshot()
	err := d.Allocate(testDebugletID, "e1", []string{first, blocked}, 10, 40)
	if !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("allocation over a full destination: %v", err)
	}
	if got := d.Snapshot(); got != before {
		t.Fatalf("failed allocation left a partial charge:\nbefore:\n%s\nafter:\n%s", before, got)
	}
	if got := d.ActiveAllocations(); got != 1 {
		t.Fatalf("%d recorded allocations after the failure, want 1", got)
	}
	if members := d.TreeMembers(first); len(members) != 1 || members["e2"] != 30 {
		t.Fatalf("fairshare membership of %s after the failure = %v", first, members)
	}
	if members := d.TreeMembers(blocked); len(members) != 0 {
		t.Fatalf("fairshare membership of %s after the failure = %v", blocked, members)
	}

	// The same request holds completely once the destination admits it.
	d.SetLimit(blocked, 100)
	if err := d.Allocate(testDebugletID, "e1", []string{first, blocked}, 10, 40); err != nil {
		t.Fatalf("allocation after the destination admits it: %v", err)
	}
	if used, want := d.Used(first), resource.Bitrate(20); used != want {
		t.Fatalf("charged floor on %s = %s, want %s", first, used, want)
	}
	for _, destination := range []string{first, blocked} {
		d.Remove(testDebugletID, destination)
	}
	d.Remove(testDebugletID2, first)
	if got := d.Snapshot(); got != "" {
		t.Fatalf("releases left residue:\n%s", got)
	}
}

// TestAllocateKeepsTotalsAcrossRunsAndDestinations states the capacity
// invariants of successful allocation and terminal release: the charged floor
// of a destination is the sum of the floors allocated on it, in any exit
// order, and the stores are empty and nonnegative once the last run is gone.
func TestAllocateKeepsTotalsAcrossRunsAndDestinations(t *testing.T) {
	d := resource.NewDestinations(1000)
	dests := []string{"128.0.0.0", "128.0.0.1", "128.0.0.2"}
	runs := []uuid.UUID{testDebugletID, testDebugletID2, testDebugletID3, testDebugletID4}
	executors := []string{"e1", "e1", "e2", "e3"}
	for i, run := range runs {
		if err := d.Allocate(run, executors[i], dests, 10, 40); err != nil {
			t.Fatalf("allocate run %d: %v", i, err)
		}
	}
	for _, destination := range dests {
		if used, want := d.Used(destination), resource.Bitrate(10*len(runs)); used != want {
			t.Fatalf("charged floor on %s = %s, want %s", destination, used, want)
		}
	}
	for i := len(runs) - 1; i >= 0; i-- {
		for _, destination := range dests {
			d.Remove(runs[i], destination)
		}
		for _, destination := range dests {
			if used, want := d.Used(destination), resource.Bitrate(10*i); used != want {
				t.Fatalf("charged floor on %s after releasing run %d = %s, want %s", destination, i, used, want)
			}
		}
	}
	if got := d.Snapshot(); got != "" {
		t.Fatalf("releases left residue:\n%s", got)
	}
	if active, charged, tracked := d.ActiveAllocations(), d.ChargedDestinations(), d.Len(); active != 0 || charged != 0 || tracked != 0 {
		t.Fatalf("after the last release: %d allocations, %d charged destinations, %d executor totals", active, charged, tracked)
	}
	for _, destination := range dests {
		if members := d.TreeMembers(destination); len(members) != 0 {
			t.Fatalf("fairshare membership of %s after the last release = %v", destination, members)
		}
	}
}

// TestRemoveKeepsRemainingAllocations states that the release of one run keeps
// every other allocation of the destination intact, including runs whose
// ceiling equals their floor and which therefore leave no residual bandwidth
// to share. The exit order never changes the outcome, and the last release
// empties every store.
func TestRemoveKeepsRemainingAllocations(t *testing.T) {
	type run struct {
		id               uuid.UUID
		executor         string
		minimum, maximum resource.Bitrate
	}
	for _, tc := range []struct {
		name string
		runs [2]run
	}{
		{"floor-only runs on one executor", [2]run{
			{testDebugletID, "e1", 10, 10}, {testDebugletID2, "e1", 20, 20}}},
		{"floor-only runs on two executors", [2]run{
			{testDebugletID, "e1", 10, 10}, {testDebugletID2, "e2", 20, 20}}},
		{"residual and floor-only run on one executor", [2]run{
			{testDebugletID, "e1", 10, 50}, {testDebugletID2, "e1", 20, 20}}},
		{"residual and floor-only run on two executors", [2]run{
			{testDebugletID, "e1", 10, 50}, {testDebugletID2, "e2", 20, 20}}},
	} {
		for first := range 2 {
			t.Run(fmt.Sprintf("%s/%d exits first", tc.name, first), func(t *testing.T) {
				d := resource.NewDestinations(100)
				dest := "128.0.0.0"
				for _, r := range tc.runs {
					if err := d.Insert(r.id, dest, r.executor, r.minimum, r.maximum); err != nil {
						t.Fatalf("allocate run %s: %v", r.id, err)
					}
				}
				leaving, staying := tc.runs[first], tc.runs[1-first]
				d.Remove(leaving.id, dest)

				limits := maps.Collect(d.Fairshare(dest))
				limit, present := limits[staying.executor]
				if !present {
					t.Fatalf("the remaining run lost its executor from the fairshare: %v", limits)
				}
				if limit < staying.minimum || limit > staying.maximum {
					t.Fatalf("remaining limit %s is outside [%s, %s]", limit, staying.minimum, staying.maximum)
				}
				if leaving.executor != staying.executor {
					if _, still := limits[leaving.executor]; still {
						t.Fatalf("the released executor is still fairshared: %v", limits)
					}
				}
				if used := d.Used(dest); used != staying.minimum {
					t.Fatalf("charged floor after the release = %s, want %s", used, staying.minimum)
				}
				if floor, ceiling, tracked := d.Totals(staying.executor, dest); !tracked || floor != staying.minimum || ceiling != staying.maximum {
					t.Fatalf("totals of the remaining run = (%s, %s, tracked=%t)", floor, ceiling, tracked)
				}

				d.Remove(staying.id, dest)
				if got := d.Snapshot(); got != "" {
					t.Fatalf("the last release left residue:\n%s", got)
				}
				if active, charged, tracked := d.ActiveAllocations(), d.ChargedDestinations(), d.Len(); active != 0 || charged != 0 || tracked != 0 {
					t.Fatalf("after the last release: %d allocations, %d charged destinations, %d executor totals", active, charged, tracked)
				}
				if members := d.TreeMembers(dest); len(members) != 0 {
					t.Fatalf("fairshare membership after the last release = %v", members)
				}
				if used := d.Used(dest); used != 0 {
					t.Fatalf("charged floor after the last release = %s", used)
				}
			})
		}
	}
}

// fairshareCounts is how often each executor is yielded for a destination.
// A consistent tree yields every member exactly once.
func fairshareCounts(d *resource.DestinationsUsage, destination string) map[string]int {
	counts := make(map[string]int)
	for id := range d.Fairshare(destination) {
		counts[id]++
	}
	return counts
}

// TestFairshareYieldsEachExecutorOnce states that the destination stores stay
// consistent while several executors share one destination and release their
// runs one by one: every remaining executor is fairshared exactly once with a
// limit within its own totals, a released executor disappears, and the last
// release empties the membership.
func TestFairshareYieldsEachExecutorOnce(t *testing.T) {
	executors := []string{"e1", "e2", "e3"}
	runs := []uuid.UUID{testDebugletID, testDebugletID2, testDebugletID3, testDebugletID4, testDebugletID5, testDebugletID6}
	for _, tc := range []struct {
		name    string
		ceiling func(run int) resource.Bitrate
	}{
		{"floor-only runs", func(int) resource.Bitrate { return 10 }},
		{"mixed residual and floor-only runs", func(run int) resource.Bitrate {
			if run%2 == 0 {
				return 40
			}
			return 10
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := resource.NewDestinations(1000)
			dest := "128.0.0.0"
			// Two runs of every executor, so releasing one leaves the executor
			// with totals that keep it a member.
			executorOf := func(run int) string { return executors[run/2] }
			for run, id := range runs {
				if err := d.Insert(id, dest, executorOf(run), 10, tc.ceiling(run)); err != nil {
					t.Fatalf("allocate run %d: %v", run, err)
				}
			}
			assertMembership := func(t *testing.T, released int) {
				t.Helper()
				remaining := make(map[string]int)
				for run := released; run < len(runs); run++ {
					remaining[executorOf(run)]++
				}
				counts := fairshareCounts(d, dest)
				if len(counts) != len(remaining) {
					t.Fatalf("after releasing %d runs, fairshare yields %v, want the executors %v", released, counts, remaining)
				}
				for executor := range remaining {
					if counts[executor] != 1 {
						t.Fatalf("after releasing %d runs, %s is fairshared %d times: %v", released, executor, counts[executor], counts)
					}
				}
				members := d.TreeMemberIDs(dest)
				if len(members) != len(remaining) {
					t.Fatalf("after releasing %d runs, tree membership is %v, want the executors %v", released, members, remaining)
				}
				for _, member := range members {
					floor, ceiling, tracked := d.Totals(member, dest)
					if !tracked {
						t.Fatalf("tree member %s has no totals", member)
					}
					limit := resource.Bitrate(0)
					for id, value := range d.Fairshare(dest) {
						if id == member {
							limit = value
						}
					}
					if limit < floor || limit > ceiling {
						t.Fatalf("limit %s of %s is outside its totals [%s, %s]", limit, member, floor, ceiling)
					}
				}
			}
			assertMembership(t, 0)
			for run, id := range runs {
				d.Remove(id, dest)
				assertMembership(t, run+1)
			}
			if got := d.Snapshot(); got != "" {
				t.Fatalf("the last release left residue:\n%s", got)
			}
			if members := d.TreeMemberIDs(dest); len(members) != 0 {
				t.Fatalf("tree membership after the last release = %v", members)
			}
			if active, charged, tracked := d.ActiveAllocations(), d.ChargedDestinations(), d.Len(); active != 0 || charged != 0 || tracked != 0 {
				t.Fatalf("after the last release: %d allocations, %d charged destinations, %d executor totals", active, charged, tracked)
			}
			if used := d.Used(dest); used != 0 {
				t.Fatalf("charged floor after the last release = %s", used)
			}
		})
	}
}
