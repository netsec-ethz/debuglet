// Bandwidth limit management on a job-basis running on the executor
package resource

import (
	"debuglet/internal/util/avl"
	"errors"
)

var (
	ErrMinGreater   = errors.New("minimum is greater than maximum bandwidth limit")
	ErrCapacityFull = errors.New("insufficient capacity")
)

type LimitManager struct {
	assignMax map[string]int64
	assignMin map[string]int64
	// The residual (limit-minimum) bandwidths of assignments available for fairsharing
	tree              *avl.AVL[string]
	capacity          int64
	minUsedCapacity   int64
	maxUsedCapacity   int64
	previousFairshare int64

	destinationLimit map[string]map[string]int64
}

func New(capacity int64) *LimitManager {
	return &LimitManager{
		assignMax: make(map[string]int64),
		assignMin: make(map[string]int64),

		tree:              &avl.AVL[string]{},
		capacity:          capacity,
		previousFairshare: -1,

		destinationLimit: make(map[string]map[string]int64),
	}
}

// InsertAssignmentCeiling registers an assignments resources, either
// when starting a new assignment or after receiving an update from the
// dispatcher.
// Returns true if fairsharing is required.
func (m *LimitManager) RegisterAssignment(assignmentID string, minimum, maximum int64) error {
	if minimum > maximum {
		return ErrMinGreater
	}
	if minimum > m.capacity-m.minUsedCapacity {
		return ErrCapacityFull
	}

	m.assignMin[assignmentID] = minimum
	m.assignMax[assignmentID] = maximum
	m.tree.Insert(assignmentID, maximum-minimum)
	m.minUsedCapacity += minimum
	m.maxUsedCapacity += maximum

	return nil
}

func (m *LimitManager) SetDestinationLimit(assignmentID, destination string, maximum int64) {
	_, exists := m.destinationLimit[assignmentID]
	if !exists {
		m.destinationLimit[assignmentID] = make(map[string]int64)
	}
	m.destinationLimit[assignmentID][destination] = maximum
}

func (m *LimitManager) RemoveAssignment(assignmentID string) (fairshareRequired bool) {
	minimum, exists := m.assignMin[assignmentID]
	if !exists {
		return false
	}
	maximum := m.assignMax[assignmentID]

	delete(m.assignMax, assignmentID)
	delete(m.assignMin, assignmentID)
	m.tree.Delete(assignmentID, maximum-minimum)
	m.minUsedCapacity -= minimum
	m.maxUsedCapacity -= maximum

	return m.maxUsedCapacity > m.capacity
}

func (m *LimitManager) UpdateCapacity(newCapacity int64) (fairshareRequired bool) {
	if newCapacity == m.capacity {
		return
	}
	m.capacity = newCapacity
	return m.maxUsedCapacity > m.capacity
}

// Fairshare computes the fairshare value with the currently registered assignments
func (m *LimitManager) Fairshare() {
	m.previousFairshare = m.tree.Fairshare(m.capacity - m.minUsedCapacity)
}

func (m *LimitManager) GetAllowedExecutor(assignmentID string) int64 {
	maximum := m.assignMax[assignmentID]
	if m.previousFairshare == -1 {
		// no fairshare
		return maximum
	}
	return min(maximum, m.previousFairshare+m.assignMin[assignmentID])
}

func (m *LimitManager) GetAllowedDestination(assignmentID, destination string) int64 {
	return m.destinationLimit[assignmentID][destination]
}
