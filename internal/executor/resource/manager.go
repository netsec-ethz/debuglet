// Bandwidth management on a job-basis running on the executor
package resource

import (
	"debuglet/internal/util/avl"
	"errors"
	"iter"
)

var (
	ErrMinGreater   = errors.New("minimum is greater than maximum bandwidth limit")
	ErrCapacityFull = errors.New("insufficient capacity")
)

type ExecutorManager struct {
	assignMax map[string]int64
	assignMin map[string]int64
	// The residual (limit-minimum) bandwidths of assignments available for fairsharing
	tree              *avl.AVL[string]
	capacity          int64
	minUsedCapacity   int64
	maxUsedCapacity   int64
	previousFairshare int64
}

func New(capacity int64) *ExecutorManager {
	return &ExecutorManager{
		tree:              &avl.AVL[string]{},
		assignMax:         make(map[string]int64),
		assignMin:         make(map[string]int64),
		capacity:          capacity,
		previousFairshare: -1,
	}
}

// InsertAssignmentCeiling registers an assignments resources, either
// when starting a new assignment or after receiving an update from the
// dispatcher.
// Returns true if fairsharing is required.
func (e *ExecutorManager) RegisterAssignment(assignmentID string, minimum, maximum int64) (bool, error) {
	if minimum > maximum {
		return false, ErrMinGreater
	}
	if minimum > e.capacity-e.minUsedCapacity {
		return false, ErrCapacityFull
	}

	e.assignMin[assignmentID] = minimum
	e.assignMax[assignmentID] = maximum
	e.tree.Insert(maximum-minimum, assignmentID)
	e.minUsedCapacity += minimum
	e.maxUsedCapacity += maximum

	return e.maxUsedCapacity > e.capacity, nil
}

func (e *ExecutorManager) RemoveAssignment(assignmentID string) (fairshareRequired bool) {
	minimum, exists := e.assignMin[assignmentID]
	if !exists {
		return false
	}
	maximum := e.assignMax[assignmentID]

	delete(e.assignMax, assignmentID)
	delete(e.assignMin, assignmentID)
	e.tree.Delete(maximum-minimum, assignmentID)
	e.minUsedCapacity -= minimum
	e.maxUsedCapacity -= maximum

	return e.maxUsedCapacity > e.capacity
}

func (e *ExecutorManager) UpdateCapacity(newCapacity int64) (fairshareRequired bool) {
	if newCapacity == e.capacity {
		return
	}
	e.capacity = newCapacity
	return e.maxUsedCapacity > e.capacity
}

func (e *ExecutorManager) Fairshare() iter.Seq2[string, int64] {
	return func(yield func(string, int64) bool) {
		fairshare := e.tree.Fairshare(e.capacity - e.minUsedCapacity)
		defer func() { e.previousFairshare = fairshare }()

		if e.previousFairshare != -1 && fairshare > e.previousFairshare {
			// reset previously fairshared nodes
			for n := range e.tree.Range(e.previousFairshare, fairshare) {
				if !yield(n.ID, e.assignMax[n.ID]) {
					return
				}
			}
		}

		for n := range e.tree.Range(fairshare, avl.Unbounded) {
			actualLimit := min(e.assignMax[n.ID], fairshare+e.assignMin[n.ID])
			if !yield(n.ID, actualLimit) {
				return
			}
		}
	}
}
