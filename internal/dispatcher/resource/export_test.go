package resource

import (
	"fmt"
	"slices"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/avl"
)

// Snapshot renders the complete destination bookkeeping in a stable order:
// every recorded allocation, the charged totals, the aggregated executor
// limits and the fairshare tree membership. Comparing two snapshots states
// that nothing at all changed in between.
func (d *DestinationsUsage) Snapshot() string {
	var lines []string
	for key, recorded := range d.activeDebuglets {
		lines = append(lines, fmt.Sprintf("active %s %s -> %s floor=%d ceil=%d", key.destination, key.id, recorded.executorID, recorded.minimum, recorded.maximum))
	}
	for destination, used := range d.usedCapacities {
		lines = append(lines, fmt.Sprintf("used %s = %d", destination, used))
	}
	for key, value := range d.store {
		lines = append(lines, fmt.Sprintf("store %s@%s floor=%d ceil=%d runs=%d", key.ID, key.destination, value.minimum, value.maximum, value.runs))
	}
	for destination, tree := range d.trees {
		for node := range tree.Range(avl.Unbounded, avl.Unbounded) {
			lines = append(lines, fmt.Sprintf("tree %s %s = %d", destination, node.ID, node.Value))
		}
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// ActiveAllocations is the number of recorded allocation decisions.
func (d *DestinationsUsage) ActiveAllocations() int { return len(d.activeDebuglets) }

// ChargedDestinations is the number of destinations holding a charged total.
func (d *DestinationsUsage) ChargedDestinations() int { return len(d.usedCapacities) }

// Used is the floor bandwidth charged on a destination.
func (d *DestinationsUsage) Used(destination string) Bitrate { return d.usedCapacities[destination] }

// Totals is the floor and ceiling an executor holds on a destination.
func (d *DestinationsUsage) Totals(executorID, destination string) (Bitrate, Bitrate, bool) {
	value, exists := d.store[storeKey{ID: executorID, destination: destination}]
	if !exists {
		return 0, 0, false
	}
	return value.minimum, value.maximum, true
}

// TreeMembers is the fairshare tree membership of a destination, mapping each
// executor to its residual bandwidth.
func (d *DestinationsUsage) TreeMembers(destination string) map[string]int64 {
	members := make(map[string]int64)
	tree, exists := d.trees[destination]
	if !exists {
		return members
	}
	for node := range tree.Range(avl.Unbounded, avl.Unbounded) {
		members[node.ID] = node.Value
	}
	return members
}

// TreeMemberIDs is the fairshare tree membership of a destination in tree
// order, repeating any executor that is a member more than once.
func (d *DestinationsUsage) TreeMemberIDs(destination string) []string {
	var members []string
	tree, exists := d.trees[destination]
	if !exists {
		return members
	}
	for node := range tree.Range(avl.Unbounded, avl.Unbounded) {
		members = append(members, node.ID)
	}
	return members
}
