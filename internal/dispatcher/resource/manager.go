// Bandwidth resource management on a destination-level running on the dispatcher
package resource

import (
	pb "debuglet/protocol"
	"fmt"
)

// TODO: Replace with dynamic capacity map
const HARDCODED_CAPACITY = 1_000_000_000 // 1gb

// Keeps track of how much capacity is used/free for executors and destinations
type DispatcherManager struct {
	// The floor usages of all jobs running on an executor
	executorUsages map[string]int64
	// Non-default max capacities of an executor
	executorCapacities map[string]int64
	// Keeps track of the floors added by jobs to later remove them again from executorUsages
	originalFloors       map[string]int64
	originalCeils        map[string]int64
	destinations         *DestinationsUsage
	originalDestinations map[string][]string
	// What jobs have been adjustments since the last fairshare.
	// Enables for only the fairshare updates to be returned that have actually changed.
	adjustments  map[string]map[string]int64
	IDtoExecutor map[string]string
}

func New() *DispatcherManager {
	return &DispatcherManager{
		executorUsages:       make(map[string]int64),
		executorCapacities:   make(map[string]int64),
		originalFloors:       make(map[string]int64),
		originalCeils:        make(map[string]int64),
		originalDestinations: make(map[string][]string),
		destinations:         NewDestinations(HARDCODED_CAPACITY),
		adjustments:          make(map[string]map[string]int64),
		IDtoExecutor:         make(map[string]string),
	}
}

func (d *DispatcherManager) CheckPolicy(executorID string, floor, ceil int64, destinations []string) error {
	execCapacity, exists := d.executorCapacities[executorID]
	if !exists {
		execCapacity = HARDCODED_CAPACITY
	}
	execUsage := d.executorUsages[executorID]
	if x := execUsage + floor; x > execCapacity {
		return fmt.Errorf("%s executor capacity exceeded (want %d, have %d): %w", executorID, floor, execCapacity-execUsage, ErrCapacityFull)
	}

	for _, dest := range destinations {
		if err := d.destinations.CheckCapacity(dest, floor); err != nil {
			return err
		}
	}

	return nil
}

func (d *DispatcherManager) RegisterPolicy(executorID string, assignment *pb.DebugletAssignment) (map[string]*pb.DestinationUpdates, error) {
	assignmentID := assignment.GetSessionId()
	policy := assignment.GetPolicy()
	if policy == nil {
		return nil, fmt.Errorf("Expected assignment policy, got nil")
	}
	destinations := policy.GetDestinations()

	d.executorUsages[assignmentID] += policy.GetFloorBw()
	d.originalFloors[assignmentID] = policy.GetFloorBw()
	d.originalCeils[assignmentID] = policy.GetCeilBw()
	d.originalDestinations[assignmentID] = destinations
	d.IDtoExecutor[assignmentID] = executorID

	// insert to dests
	for i, dest := range destinations {
		if err := d.destinations.Insert(dest, assignmentID, policy.GetFloorBw(), policy.GetCeilBw()); err != nil {
			// reset previous insertions and reject because of error
			for _, prevDest := range destinations[:i] {
				d.destinations.Remove(prevDest, assignmentID)
			}
			d.executorUsages[assignmentID] -= policy.GetFloorBw()
			delete(d.originalFloors, assignmentID)
			delete(d.originalCeils, assignmentID)
			delete(d.IDtoExecutor, assignmentID)
			return nil, err
		}
	}

	updates := d.determineUpdates(destinations)
	return updates, nil
}

func (d *DispatcherManager) RemovePolicy(assignmentID string) (map[string]*pb.DestinationUpdates, error) {
	destinations, exists := d.originalDestinations[assignmentID]
	if !exists {
		return nil, fmt.Errorf("assignment ID not found, id=%s", assignmentID)
	}
	originalFloor := d.originalFloors[assignmentID]
	d.executorUsages[assignmentID] -= originalFloor

	for _, dest := range d.originalDestinations[assignmentID] {
		d.destinations.Remove(dest, assignmentID)
	}

	delete(d.originalFloors, assignmentID)
	delete(d.originalCeils, assignmentID)
	delete(d.IDtoExecutor, assignmentID)
	delete(d.originalDestinations, assignmentID)

	updates := d.determineUpdates(destinations)
	return updates, nil
}

func (d *DispatcherManager) determineUpdates(destinations []string) map[string]*pb.DestinationUpdates {
	var rawUpdates map[string][]*pb.DestinationUpdates_Update = make(map[string][]*pb.DestinationUpdates_Update)

	for _, dest := range destinations {
		adjusted, exists := d.adjustments[dest]
		if !exists {
			adjusted = make(map[string]int64)
			d.adjustments[dest] = adjusted
		}

		for assignID, newCeil := range d.destinations.Fairshare(dest) {
			executor, exists := d.IDtoExecutor[assignID]
			if !exists {
				continue
			}
			if newCeil >= d.originalCeils[assignID] {
				if _, exists := adjusted[assignID]; exists {
					// job previously had a lower ceil for this dest. Now its back to its default value again
					delete(d.adjustments, assignID)
					rawUpdates[executor] = append(rawUpdates[executor], &pb.DestinationUpdates_Update{
						AssignmentId: assignID,
						Destination:  dest,
						NewCeilBw:    min(newCeil, d.originalCeils[assignID]),
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
	return updates
}
