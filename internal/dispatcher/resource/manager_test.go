package resource_test

import (
	"fmt"
	"runtime"
	"testing"

	"debuglet/internal/dispatcher/resource"
	pb "debuglet/protocol"
)

func TestCapacityCheck(t *testing.T) {
	rm := resource.New()
	var gbs int64 = 1_000_000_000
	rm.SetExecutorCapacity("exec-1", gbs)
	rm.SetExecutorCapacity("exec-2", gbs)

	t.Run("Success within capacity", func(t *testing.T) {
		err := rm.CheckPolicy("exec-1", 500_000, 1_000_000, []string{"dest-1", "dest-2"})
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	})

	t.Run("Executor capacity exceeded", func(t *testing.T) {
		err := rm.CheckPolicy("exec-2", gbs+1, gbs+100, []string{"dest-1"})
		if err == nil {
			t.Fatal("Expected capacity exceeded error, got nil")
		}
	})
}

func TestRegisterSingle(t *testing.T) {
	rm := resource.New()

	assignment := &pb.DebugletAssignment{
		SessionId: "session-1",
		Addresses: []string{"dest-1"},
		Policy: &pb.DebugletAssignment_Policy{
			FloorBw: 100_000,
			CeilBw:  500_000,
		},
	}

	err := rm.RegisterPolicy("exec-1", assignment)
	if err != nil {
		t.Fatalf("Expected no error during registration, got %v", err)
	}
	updates := rm.Updates(assignment.Addresses)

	if updates == nil {
		t.Fatal("Expected updates map to not be nil")
	}
}

func TestMultipleDestinations(t *testing.T) {
	rm := resource.New()

	assignment := &pb.DebugletAssignment{
		SessionId: "session-2",
		Addresses: []string{"dest-1", "dest-2", "dest-3"},
		Policy: &pb.DebugletAssignment_Policy{
			FloorBw: 200_000,
			CeilBw:  800_000,
		},
	}

	err := rm.RegisterPolicy("exec-2", assignment)
	if err != nil {
		t.Fatalf("Expected no error during registration, got %v", err)
	}
	updates := rm.Updates(assignment.Addresses)

	if updates == nil {
		t.Fatal("Expected updates map to not be nil")
	}
}

// Add 2 jobs, expect both to be capped
func TestUpdates(t *testing.T) {
	rm := resource.New()

	job1 := &pb.DebugletAssignment{
		SessionId: "session-1",
		Addresses: []string{"dest-1"},
		Policy:    &pb.DebugletAssignment_Policy{FloorBw: 200_000_000, CeilBw: 800_000_000},
	}
	err := rm.RegisterPolicy("exec-1", job1)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	updates := rm.Updates(job1.Addresses)
	if len(updates) > 0 {
		t.Fatalf("Expected no updates, got %v", updates)
	}

	job2 := &pb.DebugletAssignment{
		SessionId: "session-2",
		Addresses: []string{"dest-1"},
		Policy:    &pb.DebugletAssignment_Policy{FloorBw: 200_000_000, CeilBw: 800_000_000},
	}
	err = rm.RegisterPolicy("exec-1", job2)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	updates = rm.Updates(job2.Addresses)
	if up := updates["exec-1"]; up == nil || len(updates["exec-1"].Updates) != 2 {
		t.Fatalf("Expected 2 updates, got %v", updates["exec-1"])
	} else {
		for _, update := range up.Updates {
			if (update.AssignmentId != "session-1" && update.AssignmentId != "session-2") || update.Destination != "dest-1" || update.NewCeilBw != 500_000_000 {
				t.Fatalf("Expected even destination updates, got %v", update)
			}
		}
	}
}

// Test if the updates are the minimum possible
func TestMinimalUpdates(t *testing.T) {
	rm := resource.New()

	job1 := &pb.DebugletAssignment{SessionId: "session-1", Addresses: []string{"dest-1"}, Policy: &pb.DebugletAssignment_Policy{FloorBw: 200_000_000, CeilBw: 800_000_000}}
	job2 := &pb.DebugletAssignment{SessionId: "session-2", Addresses: []string{"dest-1"}, Policy: &pb.DebugletAssignment_Policy{FloorBw: 200_000_000, CeilBw: 800_000_000}}
	job3 := &pb.DebugletAssignment{SessionId: "session-3", Addresses: []string{"dest-1"}, Policy: &pb.DebugletAssignment_Policy{FloorBw: 100_000_000, CeilBw: 100_000_000}}

	err := rm.RegisterPolicy("exec-1", job1)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	err = rm.RegisterPolicy("exec-1", job2)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	updates := rm.Updates(job2.Addresses)
	if up := updates["exec-1"]; up == nil || len(up.Updates) != 2 {
		t.Fatalf("Expected 2 updates, got %v", updates)
	}

	// job3 should not receive an update
	err = rm.RegisterPolicy("exec-1", job3)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	updates = rm.Updates(job3.Addresses)
	if up := updates["exec-1"]; up == nil || len(up.Updates) != 2 {
		t.Fatalf("Expected 2 updates, got %v", up)
	} else {
		for _, update := range up.Updates {
			if update.AssignmentId == "session-3" {
				t.Fatalf("Expected no updates for session-3, got %v", update)
			}
		}
	}

	rm.RemovePolicy("session-2")
	updates = rm.Updates(job2.Addresses)

	if up := updates["exec-1"]; up == nil || len(up.Updates) != 1 {
		t.Fatalf("Expected no error and 1 update, got %v and updates=%v", err, up)
	} else {
		for _, update := range up.Updates {
			if update.AssignmentId == "session-3" {
				t.Fatalf("Expected no updates for session-3, got %v", update)
			}
		}
	}

}

func TestRemoveAssignment(t *testing.T) {
	rm := resource.New()

	job1 := &pb.DebugletAssignment{
		SessionId: "session-1",
		Addresses: []string{"dest-1"},
		Policy:    &pb.DebugletAssignment_Policy{FloorBw: 1_000_000_000, CeilBw: 1_000_000_000},
	}
	err := rm.RegisterPolicy("exec-1", job1)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	updates := rm.Updates(job1.Addresses)
	if len(updates) > 0 {
		t.Fatalf("Expected no updates, got %v", updates)
	}

	rm.RemovePolicy("session-1")

	job2 := &pb.DebugletAssignment{
		SessionId: "session-2",
		Addresses: []string{"dest-1"},
		Policy:    &pb.DebugletAssignment_Policy{FloorBw: 1_000_000_000, CeilBw: 1_000_000_000},
	}
	err = rm.RegisterPolicy("exec-1", job2)
	if err != nil {
		t.Fatalf("Expected no error and no updates, got %v, updates=%v", err, updates)
	}
	updates = rm.Updates(job1.Addresses)
	if len(updates) > 0 {
		t.Fatalf("Expected no updates, got %v", updates)
	}
}

const (
	benchExecutorID       = "exec-1"
	benchCapacity   int64 = 10_000_000_000
	benchFloor      int64 = 100
	benchCeil       int64 = 500
)

func newAssignment(id string, dests []string, floor, ceil int64) *pb.DebugletAssignment {
	return &pb.DebugletAssignment{
		SessionId: id,
		Addresses: dests,
		Policy: &pb.DebugletAssignment_Policy{
			FloorBw: floor,
			CeilBw:  ceil,
		},
	}
}

func seedAssignments(rm *resource.DispatcherManager, executorID string, n int, dests []string, floor, ceil int64) error {
	for i := range n {
		id := fmt.Sprintf("seed-%d", i)
		if err := rm.RegisterPolicy(executorID, newAssignment(id, dests, floor, ceil)); err != nil {
			return err
		}
	}
	return nil
}

func readMemStats() runtime.MemStats {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats
}

func reportHeapStats(b *testing.B, label string, current runtime.MemStats) {
	b.ReportMetric(float64(current.HeapAlloc), label+"heap_alloc_bytes")
	b.ReportMetric(float64(current.HeapInuse), label+"heap_inuse_bytes")
	b.ReportMetric(float64(current.Sys), label+"sys_bytes")
}

func BenchmarkCheckPolicy(b *testing.B) {
	cases := []struct {
		name     string
		existing int
		dests    []string
	}{
		{name: "N=0/single-dest", existing: 0, dests: []string{"dest-1"}},
		{name: "N=1000/single-dest", existing: 1000, dests: []string{"dest-1"}},
		{name: "N=10000/single-dest", existing: 10000, dests: []string{"dest-1"}},
		{name: "N=100_000/single-dest", existing: 100_000, dests: []string{"dest-1"}},
		{name: "N=1_000_000/single-dest", existing: 1_000_000, dests: []string{"dest-1"}},
		{name: "N=1000/multi-dest-3", existing: 1000, dests: []string{"dest-1", "dest-2", "dest-3"}},
		{name: "N=10_000/multi-dest-3", existing: 10000, dests: []string{"dest-1", "dest-2", "dest-3"}},
		{name: "N=100_000/multi-dest-3", existing: 100_000, dests: []string{"dest-1", "dest-2", "dest-3"}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			rm := resource.New()
			rm.SetExecutorCapacity(benchExecutorID, benchCapacity)

			runtime.GC()
			if err := seedAssignments(rm, benchExecutorID, tc.existing, tc.dests, benchFloor, benchCeil); err != nil {
				b.Fatalf("seed failed: %v", err)
			}
			runtime.GC()
			seedStats := readMemStats()
			reportHeapStats(b, "seed_", seedStats)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := rm.CheckPolicy(benchExecutorID, benchFloor, benchCeil, tc.dests); err != nil {
					b.Fatalf("CheckPolicy failed: %v", err)
				}
			}
			b.StopTimer()

			runtime.GC()
			postStats := readMemStats()
			reportHeapStats(b, "post_", postStats)
		})
	}
}

func BenchmarkRegisterPolicy(b *testing.B) {
	cases := []struct {
		name     string
		existing int
		dests    []string
	}{
		{name: "N=0/single-dest", existing: 0, dests: []string{"dest-1"}},
		{name: "N=1000/single-dest", existing: 1000, dests: []string{"dest-1"}},
		{name: "N=10000/single-dest", existing: 10000, dests: []string{"dest-1"}},
		{name: "N=100_000/single-dest", existing: 100_000, dests: []string{"dest-1"}},
		{name: "N=1_000_000/single-dest", existing: 1_000_000, dests: []string{"dest-1"}},
		{name: "N=1000/multi-dest-3", existing: 1000, dests: []string{"dest-1", "dest-2", "dest-3"}},
		{name: "N=10_000/multi-dest-3", existing: 10000, dests: []string{"dest-1", "dest-2", "dest-3"}},
		{name: "N=100_000/multi-dest-3", existing: 100_000, dests: []string{"dest-1", "dest-2", "dest-3"}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			rm := resource.New()
			rm.SetExecutorCapacity(benchExecutorID, benchCapacity)

			runtime.GC()
			if err := seedAssignments(rm, benchExecutorID, tc.existing, tc.dests, benchFloor, benchCeil); err != nil {
				b.Fatalf("seed failed: %v", err)
			}
			runtime.GC()
			seedStats := readMemStats()
			reportHeapStats(b, "seed_", seedStats)

			ids := make([]string, b.N)
			assignments := make([]*pb.DebugletAssignment, b.N)
			for i := 0; i < b.N; i++ {
				id := fmt.Sprintf("bench-%d", i)
				ids[i] = id
				assignments[i] = newAssignment(id, tc.dests, benchFloor, benchCeil)
			}

			batchSize := 256
			batchSize = min(batchSize, b.N)

			b.ResetTimer()
			for i := 0; i < b.N; i += batchSize {
				end := i + batchSize
				end = min(end, b.N)

				for j := i; j < end; j++ {
					if err := rm.RegisterPolicy(benchExecutorID, assignments[j]); err != nil {
						b.Fatalf("RegisterPolicy failed: %v", err)
					}
				}

				b.StopTimer()
				for j := i; j < end; j++ {
					rm.RemovePolicy(ids[j])
				}
				if end < b.N {
					b.StartTimer()
				}
			}
			b.StopTimer()

			runtime.GC()
			postStats := readMemStats()
			reportHeapStats(b, "post_", postStats)
		})
	}
}

func BenchmarkRemovePolicy(b *testing.B) {
	cases := []struct {
		name     string
		existing int
		dests    []string
	}{
		{name: "N=0/single-dest", existing: 0, dests: []string{"dest-1"}},
		{name: "N=1000/single-dest", existing: 1000, dests: []string{"dest-1"}},
		{name: "N=10000/single-dest", existing: 10000, dests: []string{"dest-1"}},
		{name: "N=100_000/single-dest", existing: 100_000, dests: []string{"dest-1"}},
		{name: "N=1_000_000/single-dest", existing: 1_000_000, dests: []string{"dest-1"}},
		{name: "N=1000/multi-dest-3", existing: 1000, dests: []string{"dest-1", "dest-2", "dest-3"}},
		{name: "N=10_000/multi-dest-3", existing: 10000, dests: []string{"dest-1", "dest-2", "dest-3"}},
		{name: "N=100_000/multi-dest-3", existing: 100_000, dests: []string{"dest-1", "dest-2", "dest-3"}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			rm := resource.New()
			rm.SetExecutorCapacity(benchExecutorID, benchCapacity)

			runtime.GC()
			if err := seedAssignments(rm, benchExecutorID, tc.existing, tc.dests, benchFloor, benchCeil); err != nil {
				b.Fatalf("seed failed: %v", err)
			}

			batchSize := 256
			batchSize = min(batchSize, b.N)

			targetIDs := make([]string, batchSize)
			targetAssignments := make([]*pb.DebugletAssignment, batchSize)
			for i := 0; i < batchSize; i++ {
				id := fmt.Sprintf("bench-target-%d", i)
				targetIDs[i] = id
				targetAssignments[i] = newAssignment(id, tc.dests, benchFloor, benchCeil)
				if err := rm.RegisterPolicy(benchExecutorID, targetAssignments[i]); err != nil {
					b.Fatalf("RegisterPolicy failed: %v", err)
				}
			}
			runtime.GC()
			seedStats := readMemStats()
			reportHeapStats(b, "seed_", seedStats)

			b.ResetTimer()
			for i := 0; i < b.N; i += batchSize {
				end := i + batchSize
				end = min(end, b.N)
				count := end - i
				for j := range count {
					rm.RemovePolicy(targetIDs[j])
				}

				b.StopTimer()
				for j := range count {
					if err := rm.RegisterPolicy(benchExecutorID, targetAssignments[j]); err != nil {
						b.Fatalf("RegisterPolicy failed: %v", err)
					}
				}
				if end < b.N {
					b.StartTimer()
				}
			}
			b.StopTimer()

			runtime.GC()
			postStats := readMemStats()
			reportHeapStats(b, "post_", postStats)
		})
	}
}

func BenchmarkUpdates(b *testing.B) {
	const (
		overCeil int64 = 800_000_000
	)

	cases := []struct {
		name     string
		existing int
		dests    []string
		floor    int64
		ceil     int64
	}{
		{name: "N=0/single-dest/under-capacity", existing: 0, dests: []string{"dest-1"}, floor: benchFloor, ceil: benchCeil},
		{name: "N=1000/single-dest/over-capacity", existing: 1000, dests: []string{"dest-1"}, floor: benchFloor, ceil: overCeil},
		{name: "N=10000/single-dest/over-capacity", existing: 10000, dests: []string{"dest-1"}, floor: benchFloor, ceil: overCeil},
		{name: "N=100_000/single-dest/over-capacity", existing: 100_000, dests: []string{"dest-1"}, floor: benchFloor, ceil: overCeil},
		{name: "N=1_000_000/single-dest/over-capacity", existing: 1_000_000, dests: []string{"dest-1"}, floor: benchFloor, ceil: overCeil},
		{name: "N=1000/multi-dest-3/over-capacity", existing: 1000, dests: []string{"dest-1", "dest-2", "dest-3"}, floor: benchFloor, ceil: overCeil},
		{name: "N=10_000/multi-dest-3/over-capacity", existing: 10000, dests: []string{"dest-1", "dest-2", "dest-3"}, floor: benchFloor, ceil: overCeil},
		{name: "N=100_000/multi-dest-3/over-capacity", existing: 100_000, dests: []string{"dest-1", "dest-2", "dest-3"}, floor: benchFloor, ceil: overCeil},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			rm := resource.New()
			rm.SetExecutorCapacity(benchExecutorID, benchCapacity)

			runtime.GC()
			if err := seedAssignments(rm, benchExecutorID, tc.existing, tc.dests, tc.floor, tc.ceil); err != nil {
				b.Fatalf("seed failed: %v", err)
			}
			runtime.GC()
			seedStats := readMemStats()
			reportHeapStats(b, "seed_", seedStats)

			_ = rm.Updates(tc.dests)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if updates := rm.Updates(tc.dests); updates == nil {
					b.Fatalf("Updates returned nil")
				}
			}
			b.StopTimer()

			runtime.GC()
			postStats := readMemStats()
			reportHeapStats(b, "post_", postStats)
		})
	}
}
