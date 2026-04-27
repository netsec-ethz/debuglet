package resource

import (
	"debuglet/internal/util/avl"
	"errors"
	"fmt"
	"iter"
)

var (
	ErrMinGreater   = errors.New("minimum is greater than maximum bandwidth limit")
	ErrCapacityFull = errors.New("insufficient capacity")
)

type jobKey struct {
	jobId, destination string
}

type DestinationsUsage struct {
	// The residual (limit-minimum) bandwidths of assignments available for fairsharing
	trees map[string]*avl.AVL[string]
	// The explicit TOTAL destination capacities
	capacities map[string]int64
	// The total capacity for a destination used up by all relevant job's minimums
	usedCapacities map[string]int64
	// The minimum capacities of jobs
	minimums   map[jobKey]int64
	maximums   map[jobKey]int64
	defaultCap int64
}

func NewDestinations(defaultCap int64) *DestinationsUsage {
	return &DestinationsUsage{
		trees:          make(map[string]*avl.AVL[string]),
		capacities:     make(map[string]int64),
		usedCapacities: make(map[string]int64),
		minimums:       make(map[jobKey]int64),
		maximums:       make(map[jobKey]int64),
		defaultCap:     defaultCap,
	}
}

func (d *DestinationsUsage) CheckCapacity(destination string, minimum int64) error {
	cap, exists := d.capacities[destination]
	if !exists {
		cap = d.defaultCap
	}
	used := d.usedCapacities[destination]
	if used+minimum > cap {
		return fmt.Errorf("%s destination capacity exceeded (want %d, have %d): %w", destination, minimum, cap-used, ErrCapacityFull)
	}
	return nil
}

func (d *DestinationsUsage) getTreeCap(destination string) (*avl.AVL[string], int64) {
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

func (d *DestinationsUsage) Insert(destination, jobId string, minimum, maximum int64) error {
	if minimum > maximum {
		return fmt.Errorf("insertion failed with min=%d>max=%d: %w", minimum, maximum, ErrMinGreater)
	}
	tree, cap := d.getTreeCap(destination)

	used := d.usedCapacities[destination]
	if used+minimum > cap {
		return fmt.Errorf("insertion failed with new usage=%d, capacity=%d: %w", used+minimum, cap, ErrCapacityFull)
	}
	d.usedCapacities[destination] += minimum

	jk := jobKey{jobId: jobId, destination: destination}
	d.minimums[jk] = minimum
	d.maximums[jk] = maximum
	tree.Insert(jobId, maximum-minimum)
	return nil
}

func (d *DestinationsUsage) Remove(destination, jobId string) {
	tree, exists := d.trees[destination]
	if !exists {
		return
	}

	jk := jobKey{jobId: jobId, destination: destination}
	minimum := d.minimums[jk]
	maximum := d.maximums[jk]
	tree.Delete(jobId, maximum-minimum)
	if tree.Len() == 0 {
		delete(d.trees, destination)
	}
	d.usedCapacities[destination] -= minimum
	if d.usedCapacities[destination] <= 0 {
		delete(d.usedCapacities, destination)
	}
	delete(d.minimums, jk)
	delete(d.maximums, jk)
}

// Number of jobs being tracked
func (d *DestinationsUsage) Len() int {
	return len(d.minimums)
}

// Fairshares a destination address, then returns an iterator with
// tuples of (job ID, new maximum bandwidth).
// All jobs that are not returned can fully use their designated bandwidth.
//
// The fairshare respects the minimum bandwidth of each job.
// It is guaranteed that job.maximum >= fairshare >= job.minimum for all jobs.
func (d *DestinationsUsage) Fairshare(destination string) iter.Seq2[string, int64] {
	tree, cap := d.getTreeCap(destination)
	usage := d.usedCapacities[destination]

	fairshare := tree.Fairshare(cap - usage)
	return func(yield func(string, int64) bool) {
		for n := range tree.Range(avl.Unbounded, avl.Unbounded) {
			jk := jobKey{jobId: n.ID, destination: destination}
			actualLimit := min(d.maximums[jk], fairshare+d.minimums[jk])
			if !yield(n.ID, actualLimit) {
				return
			}
		}
	}
}
