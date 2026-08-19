package resource_test

import (
	"debuglet/internal/dispatcher/resource"
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/google/uuid"
)

var (
	testDebugletID  = uuid.MustParse("00000000-0000-4000-8000-000000000001")
	testDebugletID2 = uuid.MustParse("00000000-0000-4000-8000-000000000002")
	testDebugletID3 = uuid.MustParse("00000000-0000-4000-8000-000000000003")
	testDebugletID4 = uuid.MustParse("00000000-0000-4000-8000-000000000004")
	testDebugletID5 = uuid.MustParse("00000000-0000-4000-8000-000000000005")
	testDebugletID6 = uuid.MustParse("00000000-0000-4000-8000-000000000006")
	testDebugletID7 = uuid.MustParse("00000000-0000-4000-8000-000000000007")
)

func TestMultiDest(t *testing.T) {
	debugletID := testDebugletID
	d := resource.NewDestinations(100)
	dests := []string{"128.0.0.0", "128.0.0.1"}
	d.Insert(debugletID, dests[0], "e1", 1, 100)
	d.Insert(debugletID, dests[0], "e2", 1, 100)
	d.Insert(debugletID, dests[1], "e2", 1, 100)

	jobCaps := maps.Collect(d.Fairshare(dests[0]))
	if len(jobCaps) != 2 || jobCaps["e1"] != 50 || jobCaps["e2"] != 50 {
		t.Fatalf("Expected equal fair sharing of D1 for both jobs, got %v", jobCaps)
	}
	jobCaps = maps.Collect(d.Fairshare(dests[1]))
	if len(jobCaps) != 1 || jobCaps["e2"] != 100 {
		t.Fatalf("Expected e1 to get full bandwidth of D2, got %v", jobCaps)
	}
}

func TestMinimum(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(testDebugletID, dest, "e1", 60, 100)
	d.Insert(testDebugletID2, dest, "e2", 0, 100)

	jobCaps := maps.Collect(d.Fairshare(dest))
	if len(jobCaps) != 2 || jobCaps["e1"] != 80 || jobCaps["e2"] != 20 {
		t.Fatalf("Expected fair share while respecting e1's minimum of 60, got %v", jobCaps)
	}
}

func TestZero(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(testDebugletID, dest, "e1", 5, 100)
	d.Insert(testDebugletID2, dest, "e2", 5, 100)
	d.Insert(testDebugletID3, dest, "j3", 20, 20)

	jobCaps := maps.Collect(d.Fairshare(dest))
	if len(jobCaps) != 3 || jobCaps["e1"] != 40 || jobCaps["e2"] != 40 || jobCaps["j3"] != 20 {
		t.Fatalf("Expected e1=40, e2=40, j3=20, got %v", jobCaps)
	}
}

func TestNotFull(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(testDebugletID, dest, "e1", 5, 5)
	d.Insert(testDebugletID2, dest, "e2", 5, 5)
	d.Insert(testDebugletID3, dest, "j3", 20, 20)

	jobCaps := maps.Collect(d.Fairshare(dest))
	if len(jobCaps) != 3 || jobCaps["e1"] != 5 || jobCaps["e2"] != 5 || jobCaps["j3"] != 20 {
		t.Fatalf("Expected e1=5, e2=5, j3=20, got %v", jobCaps)
	}
}

func TestErrors(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	err := d.Insert(testDebugletID, dest, "e2", 10, 5)
	if err == nil || !errors.Is(err, resource.ErrMinGreater) {
		t.Fatalf("Expected to receive ErrMinGreater, got %v", err)
	}

	ids := []uuid.UUID{testDebugletID2, testDebugletID3, testDebugletID4, testDebugletID5, testDebugletID6}
	for i := range 5 {
		err := d.Insert(ids[i], dest, fmt.Sprintf("j%d", i), 20, 100000)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	err = d.Insert(testDebugletID7, dest, "e2", 5, 5)
	if err == nil || !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("Expected to receive ErrCapacityFull, got %v", err)
	}
}

func TestRemove(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(testDebugletID, dest, "e1", 10, 10)
	d.Insert(testDebugletID2, dest, "e2", 20, 100)
	d.Remove(testDebugletID, dest, "e1", 10, 10)
	if x := d.Len(); x != 1 {
		t.Fatalf("Expected Len()=1, got %d", x)
	}
	jobCaps := maps.Collect(d.Fairshare(dest))
	if len(jobCaps) != 1 || jobCaps["e2"] != 100 {
		t.Fatalf("Expected sole job e2 to have the full 100, got %v", jobCaps)
	}
}

func TestAdd(t *testing.T) {
	d := resource.NewDestinations(100)
	dest := "128.0.0.0"
	d.Insert(testDebugletID, dest, "exec1", 2, 10)
	d.Insert(testDebugletID2, dest, "exec1", 10, 10)

	d.Insert(testDebugletID3, dest, "exec2", 2, 10)

	caps := maps.Collect(d.Fairshare(dest))
	if len(caps) != 2 || caps["exec1"] != 20 || caps["exec2"] != 10 {
		t.Fatalf("Expected exec1 to have 20 and exec2 to have 10, got %v", caps)
	}
}

func BenchmarkDestinationsInsert(b *testing.B) {
	for _, initial := range []int{0, 10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("Initial%d", initial), func(b *testing.B) {
			benchmarkInsertDestinations(b, initial)
		})
	}
}

func benchmarkInsertDestinations(b *testing.B, initial int) {
	b.Helper()
	b.ReportAllocs()

	d := resource.NewDestinations(100)
	for i := range initial {
		dest := fmt.Sprintf("prefill-%d", i)
		if err := d.Insert(testDebugletID, dest, "prefill-job", 1, 100); err != nil {
			b.Fatalf("prefill insert failed at %d: %v", i, err)
		}
	}

	benchDests := make([]string, b.N)
	benchIDs := make([]uuid.UUID, b.N)
	for i := 0; i < b.N; i++ {
		benchDests[i] = fmt.Sprintf("bench-%d", i)
		benchIDs[i] = uuid.New()
	}

	b.ResetTimer()
	b.StopTimer()
	const batchSize = 1024
	for i := 0; i < b.N; {
		batch := batchSize
		if remaining := b.N - i; remaining < batch {
			batch = remaining
		}

		b.StartTimer()
		for j := 0; j < batch; j++ {
			dest := benchDests[i+j]
			if err := d.Insert(benchIDs[i+j], dest, "bench-job", 1, 100); err != nil {
				b.Fatalf("benchmark insert failed at %d: %v", i+j, err)
			}
		}
		b.StopTimer()

		for j := 0; j < batch; j++ {
			d.Remove(benchIDs[i+j], benchDests[i+j], "bench-job", 1, 100)
		}
		i += batch
	}
}
