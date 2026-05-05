package resource_test

import (
	"debuglet/internal/dispatcher/resource"
	"errors"
	"fmt"
	"maps"
	"testing"
)

func TestMultiDest(t *testing.T) {
	d := resource.NewDestinations(100)
	dests := []string{"128.0.0.0", "128.0.0.1"}
	d.Insert(dests[0], "j1", 1, 100)
	d.Insert(dests[0], "j2", 1, 100)
	d.Insert(dests[1], "j2", 1, 100)

	jobCaps := maps.Collect(d.Fairshare(dests[0]))
	if len(jobCaps) != 2 || jobCaps["j1"] != 50 || jobCaps["j2"] != 50 {
		t.Fatalf("Expected equal fair sharing of D1 for both jobs, got %v", jobCaps)
	}
	jobCaps = maps.Collect(d.Fairshare(dests[1]))
	if len(jobCaps) != 1 || jobCaps["j2"] != 100 {
		t.Fatalf("Expected J1 to get full bandwidth of D2, got %v", jobCaps)
	}
}

func TestMinimum(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(dest, "j1", 60, 100)
	d.Insert(dest, "j2", 0, 100)

	jobCaps := maps.Collect(d.Fairshare(dest))
	if len(jobCaps) != 2 || jobCaps["j1"] != 80 || jobCaps["j2"] != 20 {
		t.Fatalf("Expected fair share while respecting j1's minimum of 60, got %v", jobCaps)
	}
}

func TestZero(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(dest, "j1", 5, 100)
	d.Insert(dest, "j2", 5, 100)
	d.Insert(dest, "j3", 20, 20)

	jobCaps := maps.Collect(d.Fairshare(dest))
	if len(jobCaps) != 3 || jobCaps["j1"] != 40 || jobCaps["j2"] != 40 || jobCaps["j3"] != 20 {
		t.Fatalf("Expected j1=40, j2=40, j3=20, got %v", jobCaps)
	}
}

func TestNotFull(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(dest, "j1", 5, 5)
	d.Insert(dest, "j2", 5, 5)
	d.Insert(dest, "j3", 20, 20)

	jobCaps := maps.Collect(d.Fairshare(dest))
	if len(jobCaps) != 3 || jobCaps["j1"] != 5 || jobCaps["j2"] != 5 || jobCaps["j3"] != 20 {
		t.Fatalf("Expected j1=5, j2=5, j3=20, got %v", jobCaps)
	}
}

func TestErrors(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	err := d.Insert(dest, "j2", 10, 5)
	if err == nil || !errors.Is(err, resource.ErrMinGreater) {
		t.Fatalf("Expected to receive ErrMinGreater, got %v", err)
	}

	for i := range 5 {
		err := d.Insert(dest, fmt.Sprintf("j%d", i), 20, 100000)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	err = d.Insert(dest, "j2", 5, 5)
	if err == nil || !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("Expected to receive ErrCapacityFull, got %v", err)
	}
}

func TestRemove(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(dest, "j1", 10, 10)
	d.Insert(dest, "j2", 20, 100)
	d.Remove(dest, "j1")
	if x := d.Len(); x != 1 {
		t.Fatalf("Expected Len()=1, got %d", x)
	}
	jobCaps := maps.Collect(d.Fairshare(dest))
	if len(jobCaps) != 1 || jobCaps["j2"] != 100 {
		t.Fatalf("Expected sole job j2 to have the full 100, got %v", jobCaps)
	}
}
