// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package resource

import (
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/avl"
	"iter"

	"github.com/google/uuid"
)

var (
	ErrMinGreater     = errors.New("minimum is greater than maximum bandwidth limit")
	ErrCapacityFull   = errors.New("insufficient capacity")
	ErrPolicyConflict = errors.New("destination is already allocated to the run with different limits")
)

type storeKey struct {
	// ID is used for either the debuglet ID or exeutor ID depending on the map it's used in
	ID, destination string
}

// activeKey identifies an active debuglet on a specific destination.
type activeKey struct {
	id          uuid.UUID
	destination string
}

// allocation is the decision recorded for one debuglet on one destination. It
// is immutable for the lifetime of the debuglet: a repeated request carrying
// the same values returns the recorded decision without charging again, a
// request carrying different ones is rejected, and the release subtracts
// exactly the values that were charged.
type allocation struct {
	executorID string
	minimum    Bitrate
	maximum    Bitrate
}

type storeValue struct {
	minimum Bitrate
	maximum Bitrate
	// runs is the number of allocations aggregated in this value. An executor
	// keeps its place on a destination while it holds at least one of them,
	// even when none of them leaves residual bandwidth behind.
	runs int
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
	activeDebuglets map[activeKey]allocation
	defaultCap      Bitrate
}

func NewDestinations(defaultCap Bitrate) *DestinationsUsage {
	return &DestinationsUsage{
		trees:           make(map[string]*avl.AVL[string]),
		capacities:      make(map[string]Bitrate),
		usedCapacities:  make(map[string]Bitrate),
		store:           make(map[storeKey]*storeValue),
		activeDebuglets: make(map[activeKey]allocation),
		defaultCap:      defaultCap,
	}
}

// CheckCapacity reports whether a floor still fits on a destination. The
// allocation path decides capacity itself, so this remains only as a capacity
// query for callers and tests of other packages.
func (d *DestinationsUsage) CheckCapacity(destination string, minimum Bitrate) error {
	cap := d.Cap(destination)
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
	return tree, d.Cap(destination)
}

func (d *DestinationsUsage) Cap(destination string) Bitrate {
	cap, exists := d.capacities[destination]
	if !exists {
		cap = d.defaultCap
	}
	return cap
}

// Insert records the allocation of one debuglet on a single destination. It is
// the one-destination form of Allocate and shares its behaviour.
func (d *DestinationsUsage) Insert(debugletID uuid.UUID, destination, executorID string, minimum, maximum Bitrate) error {
	return d.Allocate(debugletID, executorID, []string{destination}, minimum, maximum)
}

// Allocate records the allocation of one debuglet on every given destination
// as a single decision. A repeated destination is charged once. A destination
// already recorded for the debuglet keeps its decision, so repeating an
// identical allocation charges nothing more, while a request that changes a
// recorded decision is rejected before anything is charged. If any destination
// cannot be charged, the destinations charged by this call are released again:
// the allocation either holds for every destination or for none.
func (d *DestinationsUsage) Allocate(debugletID uuid.UUID, executorID string, destinations []string, minimum, maximum Bitrate) error {
	if minimum > maximum {
		return fmt.Errorf("allocation failed with min=%d>max=%d: %w", minimum, maximum, ErrMinGreater)
	}
	decision := allocation{executorID: executorID, minimum: minimum, maximum: maximum}
	pending := make([]string, 0, len(destinations))
	seen := make(map[string]struct{}, len(destinations))
	for _, destination := range destinations {
		if _, repeated := seen[destination]; repeated {
			continue
		}
		seen[destination] = struct{}{}
		if recorded, active := d.activeDebuglets[activeKey{debugletID, destination}]; active {
			if recorded != decision {
				return fmt.Errorf("allocation failed for an already allocated debuglet on %s: %w", destination, ErrPolicyConflict)
			}
			continue
		}
		pending = append(pending, destination)
	}
	for i, destination := range pending {
		if err := d.charge(debugletID, destination, decision); err != nil {
			for _, charged := range pending[:i] {
				d.Remove(debugletID, charged)
			}
			return err
		}
	}
	return nil
}

// charge applies a decision that is known not to be recorded yet.
func (d *DestinationsUsage) charge(debugletID uuid.UUID, destination string, decision allocation) error {
	used := d.usedCapacities[destination]
	if cap := d.Cap(destination); used+decision.minimum > cap {
		return fmt.Errorf("%s destination capacity exceeded (want %s, have %s): %w", destination, decision.minimum, cap-used, ErrCapacityFull)
	}
	tree, _ := d.getTreeCap(destination)
	d.activeDebuglets[activeKey{debugletID, destination}] = decision
	d.usedCapacities[destination] += decision.minimum
	jk := storeKey{ID: decision.executorID, destination: destination}
	total, exists := d.store[jk]
	if !exists {
		total = &storeValue{}
		d.store[jk] = total
	}
	total.minimum += decision.minimum
	total.maximum += decision.maximum
	total.runs++

	tree.Replace(decision.executorID, int64(total.maximum-total.minimum))
	return nil
}

// Remove releases the recorded allocation of one debuglet on one destination.
// The recorded decision, not the caller, determines what is subtracted, so a
// release always returns exactly the capacity its allocation charged. Removing
// an allocation that is not recorded does nothing.
func (d *DestinationsUsage) Remove(debugletID uuid.UUID, destination string) {
	key := activeKey{debugletID, destination}
	recorded, active := d.activeDebuglets[key]
	if !active {
		return
	}
	jk := storeKey{ID: recorded.executorID, destination: destination}
	total, charged := d.store[jk]
	if !charged {
		// Nothing aggregates this record. Leave the record, the charged
		// capacity and the totals as they are rather than subtracting from
		// one of them alone.
		return
	}
	delete(d.activeDebuglets, key)

	d.usedCapacities[destination] -= recorded.minimum
	if d.usedCapacities[destination] <= 0 {
		delete(d.usedCapacities, destination)
	}

	total.minimum -= recorded.minimum
	total.maximum -= recorded.maximum
	total.runs--

	tree := d.trees[destination]
	if total.runs > 0 {
		// The executor still runs other debuglets on this destination. Their
		// floors keep it in the fairshare even when they leave no residual
		// bandwidth to share, so the remaining allocations decide, never the
		// residual difference of the released one.
		if tree != nil {
			tree.Replace(recorded.executorID, int64(total.maximum-total.minimum))
		}
		return
	}

	// The last allocation of this executor on the destination is gone.
	delete(d.store, jk)
	if tree != nil {
		tree.Delete(recorded.executorID)
		if tree.Len() == 0 {
			delete(d.trees, destination)
		}
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
//
// An executor is a member of the tree of a destination exactly while it holds
// totals there, and it is a member once, so every node has its totals and each
// executor is yielded a single time.
func (d *DestinationsUsage) Fairshare(destination string) iter.Seq2[string, Bitrate] {
	tree, cap := d.getTreeCap(destination)
	usage := d.usedCapacities[destination]

	// Only what is left after the charged floors is shared. SetLimit refuses a
	// limit below what is already charged; were the capacity below it anyway,
	// nothing is shared rather than a negative share, which would take
	// bandwidth away from the floors the allocations were admitted with.
	shareable := cap - usage
	if shareable < 0 {
		shareable = 0
	}
	fairshare := tree.Fairshare(int64(shareable))
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

// SetLimit records the total capacity of a destination. A limit below the
// floors already charged there is refused and nothing is recorded: those
// floors were admitted and stay, so the limit can be lowered once they end.
func (d *DestinationsUsage) SetLimit(destination string, limit Bitrate) error {
	if used := d.usedCapacities[destination]; limit < used {
		return fmt.Errorf("%s destination limit below its charged floors (want %s, charged %s): %w", destination, limit, used, ErrCapacityFull)
	}
	d.capacities[destination] = limit
	return nil
}
