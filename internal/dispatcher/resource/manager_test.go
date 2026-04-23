package resource_test

import (
	"testing"

	"debuglet/internal/dispatcher/resource"
	pb "debuglet/protocol"
)

func TestResourceManager_CheckCapacity(t *testing.T) {
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

func TestResourceManager_RegisterAssignment_Success(t *testing.T) {
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

func TestResourceManager_RegisterAssignment_MultipleDestinations(t *testing.T) {
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
