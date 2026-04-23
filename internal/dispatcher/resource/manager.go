package resource

import (
	pb "debuglet/protocol"
	"fmt"
)

// TODO: Replace with dynamic capacity map
const HARDCODED_CAPACITY = 1_000_000_000 // 1gb

// Keeps track of how much capacity is used/free for executors and destinations
type ResourceManager struct {
	// The floor usages of all jobs running on an executor
	executorUsages map[string]int64
	// Non-default max capacities of an executor
	executorCapacities map[string]int64
	// Keeps track of the floors added by jobs to later remove them again from executorUsages
	originalFloors map[string]int64
	originalCeils  map[string]int64
	destinations   *DestinationsUsage
	// What jobs have been adjustments since the last fairshare.
	// Enables for only the fairshare updates to be returned that have actually changed.
	adjustments  map[string]map[string]int64
	IDtoExecutor map[string]string
}

func New() *ResourceManager {
	return &ResourceManager{
		executorUsages:     make(map[string]int64),
		executorCapacities: make(map[string]int64),
		originalFloors:     make(map[string]int64),
		originalCeils:      make(map[string]int64),
		destinations:       NewDestinations(HARDCODED_CAPACITY),
		adjustments:        make(map[string]map[string]int64),
		IDtoExecutor:       make(map[string]string),
	}
}

func (r *ResourceManager) CheckPolicy(executorID string, floor, ceil int64, destinations []string) error {
	execCapacity, exists := r.executorCapacities[executorID]
	if !exists {
		execCapacity = HARDCODED_CAPACITY
	}
	execUsage := r.executorUsages[executorID]
	if x := execUsage + floor; x > execCapacity {
		return fmt.Errorf("%s executor capacity exceeded (want %d, have %d): %w", executorID, floor, execCapacity-execUsage, ErrCapacityFull)
	}

	for _, dest := range destinations {
		if err := r.destinations.CheckCapacity(dest, floor); err != nil {
			return err
		}
	}

	return nil
}

func (r *ResourceManager) RegisterPolicy(executorID string, assignment *pb.DebugletAssignment) (map[string]*pb.DestinationUpdates, error) {
	r.executorUsages[assignment.SessionId] += assignment.Policy.FloorBw
	r.originalFloors[assignment.SessionId] = assignment.Policy.FloorBw
	r.originalCeils[assignment.SessionId] = assignment.Policy.CeilBw
	r.IDtoExecutor[assignment.SessionId] = executorID

	var rawUpdates map[string][]*pb.DestinationUpdates_Update

	for i, dest := range assignment.Policy.Destinations {

		if err := r.destinations.Insert(dest, assignment.SessionId, assignment.Policy.FloorBw, assignment.Policy.CeilBw); err != nil {
			// reset previous insertions and reject because of error
			for _, prevDest := range assignment.Policy.Destinations[:i] {
				r.destinations.Remove(prevDest, assignment.SessionId)
			}
			r.executorUsages[assignment.SessionId] -= assignment.Policy.FloorBw
			delete(r.originalFloors, assignment.SessionId)
			delete(r.originalCeils, assignment.SessionId)
			delete(r.IDtoExecutor, assignment.SessionId)
			return nil, err
		}

		adjusted, exists := r.adjustments[dest]
		if !exists {
			adjusted = make(map[string]int64)
			r.adjustments[dest] = adjusted
		}

		for assignID, newCeil := range r.destinations.Fairshare(dest) {
			executor, exists := r.IDtoExecutor[assignID]
			if !exists {
				continue
			}
			if newCeil >= r.originalCeils[assignID] {
				if _, exists := adjusted[assignID]; exists {
					// job previously had a lower ceil for this dest. Now its back to its default value again
					delete(r.adjustments, assignID)
					rawUpdates[executor] = append(rawUpdates[executor], &pb.DestinationUpdates_Update{
						AssignmentId: assignID,
						Destination:  dest,
						NewCeilBw:    min(newCeil, r.originalCeils[assignID]),
					})

				}
			} else {
				adjusted[assignID] = newCeil
				rawUpdates[executor] = append(rawUpdates[executor], &pb.DestinationUpdates_Update{
					AssignmentId: assignID,
					Destination:  dest,
					NewCeilBw:    newCeil,
				})
			}
		}
	}

	var updates map[string]*pb.DestinationUpdates = make(map[string]*pb.DestinationUpdates)
	for exec, update := range rawUpdates {
		updates[exec] = &pb.DestinationUpdates{Updates: update}
	}
	return updates, nil
}

func (r *ResourceManager) RemoveAssignment(assignmentID string) map[string]*pb.DestinationUpdates {
	originalFloor := r.originalFloors[assignmentID]
	r.executorUsages[assignmentID] -= originalFloor
	delete(r.originalFloors, assignmentID)
	delete(r.originalCeils, assignmentID)
	delete(r.IDtoExecutor, assignmentID)

	// TODO: updates
	return nil
}
