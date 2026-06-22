package resource

import (
	"debuglet/internal/dispatcher/resource/avl"
	"errors"
	"fmt"
	"iter"
)

var (
	ErrMinGreater   = errors.New("minimum is greater than maximum bandwidth limit")
	ErrCapacityFull = errors.New("insufficient capacity")
)

type storeKey struct {
	// ID is used for either the debuglet ID or exeutor ID depending on the map it's used in
	ID, destination string
}

type storeValue struct {
	minimum Bitrate
	maximum Bitrate
}

type DestinationsUsage struct {
	// The residual (limit-minimum) bandwidths of assignments available for fairsharing
	trees map[string]*avl.AVL[string]
	// The explicit TOTAL destination capacities
	capacities map[string]Bitrate
	// The total capacity for a destination used up by all relevant job's minimums
	usedCapacities map[string]Bitrate
	// The minimum capacities of jobs
	store           map[storeKey]*storeValue
	activeDebuglets map[storeKey]struct{}
	defaultCap      Bitrate
}

func NewDestinations(defaultCap Bitrate) *DestinationsUsage {
	return &DestinationsUsage{
		trees:           make(map[string]*avl.AVL[string]),
		capacities:      make(map[string]Bitrate),
		usedCapacities:  make(map[string]Bitrate),
		store:           make(map[storeKey]*storeValue),
		activeDebuglets: make(map[storeKey]struct{}),
		defaultCap:      defaultCap,
	}
}

func (d *DestinationsUsage) CheckCapacity(destination string, minimum Bitrate) error {
	cap, exists := d.capacities[destination]
	if !exists {
		cap = d.defaultCap
	}
	used := d.usedCapacities[destination]
	if used+minimum > cap {
		return fmt.Errorf("%s destination capacity exceeded (want %s, have %s): %w", destination, minimum, cap-used, ErrCapacityFull)
	}
	return nil
}

func (d *DestinationsUsage) getTreeCap(destination string) (*avl.AVL[string], Bitrate) {
	tree, exists := d.trees[destination]
	if !exists {
		tree = &avl.AVL[string]{}
		d.trees[destination] = tree
	}
	cap, exists := d.capacities[destination]
	if !exists {
		cap = d.defaultCap
	}
	return tree, cap
}

func (d *DestinationsUsage) Insert(debugletID string, destination, executorID string, minimum, maximum Bitrate) error {
	if minimum > maximum {
		return fmt.Errorf("insertion failed with min=%d>max=%d: %w", minimum, maximum, ErrMinGreater)
	}
	tree, cap := d.getTreeCap(destination)

	used := d.usedCapacities[destination]
	if used+minimum > cap {
		return fmt.Errorf("insertion failed with new usage=%d, capacity=%d: %w", used+minimum, cap, ErrCapacityFull)

	}
	d.activeDebuglets[storeKey{debugletID, destination}] = struct{}{}
	d.usedCapacities[destination] += minimum
	jk := storeKey{ID: executorID, destination: destination}
	if old, exists := d.store[jk]; exists {
		old.minimum += minimum
		old.maximum += maximum
	} else {
		d.store[jk] = &storeValue{minimum: minimum, maximum: maximum}
	}

	tree.Add(executorID, int64(maximum-minimum))
	return nil
}

func (d *DestinationsUsage) Remove(debugletID, destination, executorID string, minimum, maximum Bitrate) {
	if _, exists := d.activeDebuglets[storeKey{debugletID, destination}]; !exists {
		return
	}

	tree, exists := d.trees[destination]
	if !exists {
		return
	}

	node := tree.Get(executorID)
	if node == nil {
		return
	}

	jk := storeKey{ID: executorID, destination: destination}
	old, exists := d.store[jk]
	if !exists {
		return
	}

	diff := int64(maximum - minimum)
	if diff >= node.Value {
		// there is no more usage on the destination for this executor after the removal
		tree.Delete(executorID)
		if tree.Len() == 0 {
			delete(d.trees, destination)
		}
	} else {
		// there is still usage on the destination for this executor. Do not fully remove
		tree.Replace(executorID, node.Value-diff)
	}

	d.usedCapacities[destination] -= minimum
	if d.usedCapacities[destination] <= 0 {
		delete(d.usedCapacities, destination)
	}

	delete(d.activeDebuglets, storeKey{debugletID, destination})

	old.minimum -= minimum
	old.maximum -= maximum
	if old.minimum <= 0 && old.maximum <= 0 {
		delete(d.store, jk)
	}
}

// Number of IDs being tracked
func (d *DestinationsUsage) Len() int {
	return len(d.store)
}

// Fairshares a destination address, then returns an iterator with
// tuples of (ID, new maximum bandwidth).
//
// The fairshare respects the minimum bandwidth of each ID.
// It is guaranteed that ID.maximum >= fairshare >= ID.minimum for all IDs.
func (d *DestinationsUsage) Fairshare(destination string) iter.Seq2[string, Bitrate] {
	tree, cap := d.getTreeCap(destination)
	usage := d.usedCapacities[destination]

	fairshare := tree.Fairshare(int64(cap - usage))
	return func(yield func(string, Bitrate) bool) {
		for n := range tree.Range(avl.Unbounded, avl.Unbounded) {
			jk := storeKey{ID: n.ID, destination: destination}
			s := d.store[jk]
			actualLimit := min(s.maximum, Bitrate(fairshare)+s.minimum)
			if !yield(n.ID, actualLimit) {
				return
			}
		}
	}
}

func (d *DestinationsUsage) SetLimit(destination string, limit Bitrate) {
	d.capacities[destination] = limit
}
