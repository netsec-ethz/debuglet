package resource

import (
	"errors"
	"testing"

	"github.com/google/uuid"
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
	floors := map[string]Bitrate{"dlm-a": 30, "dlm-b": 20}
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
