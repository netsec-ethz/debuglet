package resource

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
)

// TestSetLimitRefusesALimitBelowTheChargedFloors states that a destination
// limit cannot be lowered below the floors already charged on it: the refusal
// records nothing, and a limit equal to those floors is accepted.
func TestSetLimitRefusesALimitBelowTheChargedFloors(t *testing.T) {
	d := NewDestinations(1000)
	const dest = "192.0.2.100"
	if err := d.Insert(uuid.New(), dest, "dlm-a", 30, 80); err != nil {
		t.Fatal(err)
	}
	if err := d.Insert(uuid.New(), dest, "dlm-b", 20, 50); err != nil {
		t.Fatal(err)
	}
	if err := d.SetLimit(dest, 49); !errors.Is(err, ErrCapacityFull) {
		t.Fatalf("limit below the charged floors returned %v, want %v", err, ErrCapacityFull)
	}
	if got := d.Cap(dest); got != 1000 {
		t.Fatalf("refused limit left the capacity at %s, want 1000", got)
	}
	if err := d.SetLimit(dest, 50); err != nil {
		t.Fatalf("limit equal to the charged floors: %v", err)
	}
	if got := d.Cap(dest); got != 50 {
		t.Fatalf("accepted limit recorded as %s, want 50", got)
	}
}

// TestFairshareKeepsFloorsBelowTheLimit pins the clamp of Fairshare: with the
// capacity below the charged floors, a state SetLimit no longer produces, each
// executor is still given exactly its summed floor, never less.
func TestFairshareKeepsFloorsBelowTheLimit(t *testing.T) {
	d := NewDestinations(1000)
	const dest = "192.0.2.101"
	floors := map[string]bitrate.Bitrate{"dlm-a": 30, "dlm-b": 20}
	if err := d.Insert(uuid.New(), dest, "dlm-a", 10, 80); err != nil {
		t.Fatal(err)
	}
	if err := d.Insert(uuid.New(), dest, "dlm-a", 20, 40); err != nil {
		t.Fatal(err)
	}
	if err := d.Insert(uuid.New(), dest, "dlm-b", 20, 50); err != nil {
		t.Fatal(err)
	}
	d.capacities[dest] = d.usedCapacities[dest] - 1
	yielded := 0
	for id, limit := range d.Fairshare(dest) {
		yielded++
		if want := floors[id]; limit != want {
			t.Fatalf("executor %s given %s below the limit, want its floors %s", id, limit, want)
		}
	}
	if yielded != len(floors) {
		t.Fatalf("fairshare yielded %d executors, want %d", yielded, len(floors))
	}
}

// TestDenyRefusesEveryFloorAndAllowRestores states that a denied destination
// refuses new allocations and capacity queries whatever their floor, zero
// included, that a recorded allocation stays and is shared zero, and that
// Allow restores admission without touching the limit.
func TestDenyRefusesEveryFloorAndAllowRestores(t *testing.T) {
	d := NewDestinations(1000)
	const dest = "192.0.2.110"
	held := uuid.New()
	if err := d.Insert(held, dest, "dlm-a", 10, 80); err != nil {
		t.Fatal(err)
	}
	if err := d.SetLimit(dest, 500); err != nil {
		t.Fatal(err)
	}
	before := d.Snapshot()
	d.Deny(dest)
	if !d.Denied(dest) {
		t.Fatal("denied destination not reported as denied")
	}
	for _, floor := range []bitrate.Bitrate{0, 10} {
		if err := d.CheckCapacity(dest, floor); !errors.Is(err, ErrDenied) {
			t.Fatalf("CheckCapacity(floor %s) = %v, want %v", floor, err, ErrDenied)
		}
		if err := d.Allocate(uuid.New(), "dlm-b", []string{"192.0.2.111", dest}, floor, 80); !errors.Is(err, ErrDenied) {
			t.Fatalf("Allocate(floor %s) = %v, want %v", floor, err, ErrDenied)
		}
	}
	if after := d.Snapshot(); after != before {
		t.Fatalf("refused allocations changed the bookkeeping:\n%s\nwant\n%s", after, before)
	}
	for id, limit := range d.Fairshare(dest) {
		if id != "dlm-a" || limit != 0 {
			t.Fatalf("denied destination shared %s to %s, want 0 to dlm-a", limit, id)
		}
	}
	if got := d.Cap(dest); got != 500 {
		t.Fatalf("deny changed the limit to %s", got)
	}
	d.Allow(dest)
	if err := d.Allocate(uuid.New(), "dlm-b", []string{dest}, 0, 80); err != nil {
		t.Fatalf("allocation after Allow: %v", err)
	}
	d.Remove(held, dest)
	if got := d.Used(dest); got != 0 {
		t.Fatalf("release of the allocation held through the deny left %s charged", got)
	}
}

// TestLimitAndDenyAreIndependent states that a zero limit is not a deny: it
// still admits a zero floor, and ResetLimit returns to the default.
func TestLimitAndDenyAreIndependent(t *testing.T) {
	d := NewDestinations(1000)
	const dest = "192.0.2.112"
	if err := d.SetLimit(dest, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckCapacity(dest, 0); err != nil {
		t.Fatalf("zero limit refused a zero floor: %v", err)
	}
	if err := d.CheckCapacity(dest, 1); !errors.Is(err, ErrCapacityFull) {
		t.Fatalf("zero limit admitted a floor: %v", err)
	}
	d.ResetLimit(dest)
	if got := d.Cap(dest); got != 1000 {
		t.Fatalf("reset limit is %s, want the default 1000", got)
	}
}
