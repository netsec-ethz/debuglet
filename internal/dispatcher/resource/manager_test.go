package resource_test

import (
	"testing"

	"debuglet/internal/dispatcher/resource"
	pb "debuglet/protocol"
)

func TestCapacityCheck(t *testing.T) {
	rm := resource.New()

	t.Run("Success within capacity", func(t *testing.T) {
		err := rm.CheckPolicy("exec-1", 500_000, 1_000_000, []string{"dest-1", "dest-2"})
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	})

	t.Run("Executor capacity exceeded", func(t *testing.T) {
		err := rm.CheckPolicy("exec-2", resource.HARDCODED_CAPACITY+1, resource.HARDCODED_CAPACITY+100, []string{"dest-1"})
		if err == nil {
			t.Fatal("Expected capacity exceeded error, got nil")
		}
	})
}

func TestRegisterSingle(t *testing.T) {
	rm := resource.New()

	assignment := &pb.DebugletAssignment{
		SessionId: "session-1",
		Policy: &pb.DebugletAssignment_Policy{
			FloorBw:      100_000,
			CeilBw:       500_000,
			Destinations: []string{"dest-1"},
		},
	}

	updates, err := rm.RegisterPolicy("exec-1", assignment)
	if err != nil {
		t.Fatalf("Expected no error during registration, got %v", err)
	}

	if updates == nil {
		t.Fatal("Expected updates map to not be nil")
	}
}

func TestMultipleDestinations(t *testing.T) {
	rm := resource.New()

	assignment := &pb.DebugletAssignment{
		SessionId: "session-2",
		Policy: &pb.DebugletAssignment_Policy{
			FloorBw:      200_000,
			CeilBw:       800_000,
			Destinations: []string{"dest-1", "dest-2", "dest-3"},
		},
	}

	updates, err := rm.RegisterPolicy("exec-2", assignment)
	if err != nil {
		t.Fatalf("Expected no error during registration, got %v", err)
	}

	if updates == nil {
		t.Fatal("Expected updates map to not be nil")
	}
}

// Add 2 jobs, expect both to be capped
func TestUpdates(t *testing.T) {
	rm := resource.New()

	job1 := &pb.DebugletAssignment{
		SessionId: "session-1",
		Policy:    &pb.DebugletAssignment_Policy{FloorBw: 200_000_000, CeilBw: 800_000_000, Destinations: []string{"dest-1"}},
	}
	updates, err := rm.RegisterPolicy("exec-1", job1)
	if err != nil || len(updates) > 0 {
		t.Fatalf("Expected no error and no updates, got %v, updates=%v", err, updates)
	}

	job2 := &pb.DebugletAssignment{
		SessionId: "session-2",
		Policy:    &pb.DebugletAssignment_Policy{FloorBw: 200_000_000, CeilBw: 800_000_000, Destinations: []string{"dest-1"}},
	}
	updates, err = rm.RegisterPolicy("exec-1", job2)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
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

	job1 := &pb.DebugletAssignment{SessionId: "session-1", Policy: &pb.DebugletAssignment_Policy{FloorBw: 200_000_000, CeilBw: 800_000_000, Destinations: []string{"dest-1"}}}
	job2 := &pb.DebugletAssignment{SessionId: "session-2", Policy: &pb.DebugletAssignment_Policy{FloorBw: 200_000_000, CeilBw: 800_000_000, Destinations: []string{"dest-1"}}}
	job3 := &pb.DebugletAssignment{SessionId: "session-3", Policy: &pb.DebugletAssignment_Policy{FloorBw: 100_000_000, CeilBw: 100_000_000, Destinations: []string{"dest-1"}}}

	_, err := rm.RegisterPolicy("exec-1", job1)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	updates, err := rm.RegisterPolicy("exec-1", job2)
	if up := updates["exec-1"]; err != nil || up == nil || len(up.Updates) != 2 {
		t.Fatalf("Expected no error and 2 updates, got %v and updates=%v", err, up)
	}
	// job3 should not receive an update
	updates, err = rm.RegisterPolicy("exec-1", job3)
	if up := updates["exec-1"]; err != nil || up == nil || len(up.Updates) != 2 {
		t.Fatalf("Expected no error and 2 updates, got %v and updates=%v", err, up)
	} else {
		for _, update := range up.Updates {
			if update.AssignmentId == "session-3" {
				t.Fatalf("Expected no updates for session-3, got %v", update)
			}
		}
	}

	updates, err = rm.RemoveAssignment("session-2")
	if up := updates["exec-1"]; err != nil || up == nil || len(up.Updates) != 1 {
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

	_, err := rm.RemoveAssignment("random-id")
	if err == nil {
		t.Fatalf("Expected nonexistent ID to return error, got nil")
	}

	job1 := &pb.DebugletAssignment{
		SessionId: "session-1",
		Policy:    &pb.DebugletAssignment_Policy{FloorBw: 1_000_000_000, CeilBw: 1_000_000_000, Destinations: []string{"dest-1"}},
	}
	updates, err := rm.RegisterPolicy("exec-1", job1)
	if err != nil || len(updates) > 0 {
		t.Fatalf("Expected no error and no updates, got %v, updates=%v", err, updates)
	}

	updates, err = rm.RemoveAssignment("session-1")
	if len(updates) > 0 || err != nil {
		t.Fatalf("Expected no updates, got %v", updates)
	}

	job2 := &pb.DebugletAssignment{
		SessionId: "session-2",
		Policy:    &pb.DebugletAssignment_Policy{FloorBw: 1_000_000_000, CeilBw: 1_000_000_000, Destinations: []string{"dest-1"}},
	}
	updates, err = rm.RegisterPolicy("exec-1", job2)
	if err != nil || len(updates) > 0 {
		t.Fatalf("Expected no error and no updates, got %v, updates=%v", err, updates)
	}
}
