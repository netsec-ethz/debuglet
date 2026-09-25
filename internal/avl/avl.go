// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package avl

import (
	"fmt"
	"iter"
	"strings"
)

type Node[T comparable] struct {
	ID T
	// Sum/Count of all (recursive) children+itself
	sum, count int64
	// h is the height of its children. 0 if it has no children.
	Value, bal, h int64
	Parent, L, R  *Node[T]
}

func newNode[T comparable](refs map[T]*Node[T], par *Node[T], v int64, id T) *Node[T] {
	n := &Node[T]{Parent: par,
		Value: v,
		sum:   v,
		count: 1,
		ID:    id,
	}
	if _, exists := refs[id]; exists {
		panic(fmt.Sprintf("duplicate ID '%v' on insert", id))
	}
	refs[id] = n
	return n
}

func (n Node[T]) String() string {
	return fmt.Sprintf("Node[%v]", n.ID)
}

func (n Node[T]) Detailed() string {
	return fmt.Sprintf("Node[v=%d,b=%d,h=%d,s=%d,c=%d]{ l:%s, r:%s }", n.Value, n.bal, n.h, n.sum, n.count, n.L, n.R)
}

func (n Node[T]) GraphDot() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\"%v\" [label=\"id=%v,\\nval=%d\\nbal=%d\\nheight=%d\\nsum=%d\\ncount=%d\"];", n.ID, n.ID, n.Value, n.bal, n.h, n.sum, n.count)
	if n.L != nil {
		b.WriteByte('\n')
		b.WriteString(n.L.GraphDot())
		fmt.Fprintf(&b, "\n\"%v\" -> \"%v\" [label=\"L\"]", n.ID, n.L.ID)
	}
	if n.R != nil {
		b.WriteByte('\n')
		b.WriteString(n.R.GraphDot())
		fmt.Fprintf(&b, "\n\"%v\" -> \"%v\" [label=\"R\"]", n.ID, n.R.ID)
	}
	return b.String()
}

func (n *Node[T]) recompute() {
	var lh, rh, lsum, lc, rsum, rc int64
	if n.L != nil {
		lh = n.L.h + 1
		lsum = n.L.sum
		lc = n.L.count
	}
	if n.R != nil {
		rh = n.R.h + 1
		rsum = n.R.sum
		rc = n.R.count
	}
	n.bal = rh - lh
	n.h = max(lh, rh)
	n.sum = n.Value + lsum + rsum
	n.count = 1 + lc + rc
}

func (n *Node[T]) rotLeft() *Node[T] {
	rightChild := n.R
	n.R = rightChild.L
	if n.R != nil {
		n.R.Parent = n
	}
	rightChild.L = n
	n.Parent = rightChild
	n.recompute()
	rightChild.recompute()
	return rightChild
}

func (n *Node[T]) rotRight() *Node[T] {
	leftChild := n.L
	n.L = leftChild.R
	if n.L != nil {
		n.L.Parent = n
	}
	leftChild.R = n
	n.Parent = leftChild
	n.recompute()
	leftChild.recompute()
	return leftChild
}

func (n *Node[T]) rotate() *Node[T] {
	if n.bal <= 1 && n.bal >= -1 {
		return n
	}
	if n.bal == 2 && n.R.bal < 0 {
		n.R = n.R.rotRight()
	} else if n.bal == -2 && n.L.bal > 0 {
		n.L = n.L.rotLeft()
	}
	var newRoot *Node[T] = n
	switch n.bal {
	case 2:
		newRoot = n.rotLeft()
	case -2:
		newRoot = n.rotRight()
	}
	return newRoot
}

// insert adds the given element at the correct location and returns
// a pointer to the newly computed root
func (n *Node[T]) insert(refs map[T]*Node[T], id T, v int64) *Node[T] {
	if v <= n.Value {
		if n.L == nil {
			n.L = newNode(refs, n, v, id)
		} else {
			n.L = n.L.insert(refs, id, v)
		}
	} else {
		if n.R == nil {
			n.R = newNode(refs, n, v, id)
		} else {
			n.R = n.R.insert(refs, id, v)
		}
	}
	n.recompute()
	return n.rotate()
}

func (n *Node[T]) minNode() *Node[T] {
	if n.L == nil {
		return n
	} else {
		return n.L.minNode()
	}
}

func (toDelete *Node[T]) deleteNode(refs map[T]*Node[T]) *Node[T] {
	// Trivial case: if either child is null, replace the
	// to-be-deleted Node with it's child
	if toDelete.L == nil || toDelete.R == nil {
		var newChild *Node[T]
		if toDelete.L != nil {
			newChild = toDelete.L
		} else {
			newChild = toDelete.R
		}

		if newChild != nil {
			newChild.Parent = toDelete.Parent
		}
		return newChild
	}

	// Two children case: take the smallest node 'toReplace' on the right side,
	// then replace the to-be-deleted Node's values with that node 'toReplace'
	// and then simply delete the old 'toReplace'
	toReplace := toDelete.R.minNode()
	refs[toReplace.ID] = toDelete

	toDelete.Value = toReplace.Value
	toDelete.ID = toReplace.ID

	toDelete.R, _ = toDelete.R.delete(refs, toReplace.ID, toReplace.Value)

	toDelete.recompute()
	return toDelete.rotate()
}

// delete removes the node with the given ID and reports whether it did.
//
// Insertion keeps every left subtree at or below its node and every right
// subtree at or above it, but rebalancing can move a node into the subtree of
// another node holding the same value. An equal value therefore identifies no
// single side, and the search continues into the other one until the actual
// identity matches. A strictly smaller or larger value still selects one side.
func (n *Node[T]) delete(refs map[T]*Node[T], id T, v int64) (*Node[T], bool) {
	if n == nil {
		return nil, false
	}
	if id == n.ID {
		return n.deleteNode(refs), true
	}
	var deleted bool
	if v <= n.Value {
		n.L, deleted = n.L.delete(refs, id, v)
		if !deleted && v == n.Value {
			n.R, deleted = n.R.delete(refs, id, v)
		}
	} else {
		n.R, deleted = n.R.delete(refs, id, v)
	}
	if !deleted {
		return n, false
	}

	n.recompute()
	return n.rotate(), true
}

const Unbounded int64 = -1

// Basic AVL tree implementation.
//
// Nodes require an ID (for example a job ID) for insertion.
// The ID itself is not used for any balancing. IDs are assumed
// to be unique.
//
// It supports multiple nodes with the same values. Hence why
// retrieving a value bases bases around ranges.
type AVL[T comparable] struct {
	root *Node[T]
	refs map[T]*Node[T]
}

func (a AVL[T]) String() string {
	if a.root == nil {
		return "AVL{nil}"
	}
	return fmt.Sprintf("AVL{ %s }", a.root.String())
}

func (a AVL[T]) GraphDot() string {
	if a.root == nil {
		return "digraph G {}"
	}
	return fmt.Sprintf("digraph G {\n%s\n}", a.root.GraphDot())
}

func (a *AVL[T]) Insert(id T, v int64) {
	if v < 0 {
		panic("negative values are unsupported")
	}
	if a.refs == nil {
		a.refs = make(map[T]*Node[T])
	}
	if a.root == nil {
		a.root = newNode(a.refs, nil, v, id)
	} else {
		a.root = a.root.insert(a.refs, id, v)
	}
}

func (a *AVL[T]) Delete(id T) {
	if a.root == nil || a.refs == nil {
		return
	}
	old, exists := a.refs[id]
	if !exists {
		return
	}
	root, deleted := a.root.delete(a.refs, id, old.Value)
	if !deleted {
		return // Retain the reference rather than losing a live member.
	}
	a.root = root
	delete(a.refs, id)
}

// Replace deletes any old nodes with the given id if they exist, and inserts
// a completely new node with the new value. Preferred over Insert if it's not
// clear if the id has already been inserted.
func (a *AVL[T]) Replace(id T, newV int64) {
	if a.refs == nil {
		a.refs = make(map[T]*Node[T])
	}
	a.Delete(id)
	a.Insert(id, newV)
}

// Add adds the value v to the node with ID id and recomputes the tree.
func (a *AVL[T]) Add(id T, v int64) {
	if a.refs == nil {
		a.refs = make(map[T]*Node[T])
	}
	old, exists := a.refs[id]
	if !exists {
		a.Insert(id, v)
	} else {
		a.Replace(id, old.Value+v)
	}
}

func (n *Node[T]) yieldRange(yield func(*Node[T]) bool, from, to int64) bool {
	fromOk := from == Unbounded || n.Value >= from
	toOk := to == Unbounded || n.Value < to
	if fromOk && toOk {
		if !yield(n) {
			return false
		}
	}
	if fromOk && n.L != nil {
		if !n.L.yieldRange(yield, from, to) {
			return false
		}
	}
	if toOk && n.R != nil {
		if !n.R.yieldRange(yield, from, to) {
			return false
		}
	}
	return true
}

// Range returns an iterator of nodes with values in the range [from, to).
// avl.Unbounded may be passed in to either argument to include all elements
// from either range.
func (a AVL[T]) Range(from, to int64) iter.Seq[*Node[T]] {
	return func(yield func(*Node[T]) bool) {
		if a.root == nil {
			return
		}
		a.root.yieldRange(yield, from, to)
	}
}

func (a AVL[T]) Get(id T) *Node[T] {
	if a.root == nil || a.refs == nil {
		return nil
	}
	return a.refs[id]
}

func (n *Node[T]) fairshare(cap int64, leftSum int64, rightCount int64) int64 {
	countLarger := rightCount
	if n.R != nil {
		countLarger += n.R.count
	}

	sumSmaller := leftSum
	if n.L != nil {
		sumSmaller += n.L.sum
	}
	sumSmaller += n.Value
	totalIfLambdaIsNode := sumSmaller + (countLarger * n.Value)

	if cap <= totalIfLambdaIsNode {
		if n.L == nil {
			return (cap - leftSum) / (1 + countLarger)
		}
		return n.L.fairshare(cap, leftSum, 1+countLarger)
	} else {
		if n.R == nil {
			if rightCount == 0 {
				return n.Value
			}
			return (cap - sumSmaller) / rightCount
		}
		return n.R.fairshare(cap, sumSmaller, rightCount)
	}
}

// Fairshare determines the maximum allowed capacity for all added nodes to be fairshared.
func (a AVL[T]) Fairshare(cap int64) int64 {
	if a.root == nil {
		return 0
	}
	return a.root.fairshare(cap, 0, 0)
}

func (a AVL[T]) Len() int64 {
	if a.root == nil {
		return 0
	}
	return a.root.count
}

func (a AVL[T]) Sum() int64 {
	if a.root == nil {
		return 0
	}
	return a.root.sum
}
