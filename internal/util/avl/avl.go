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

func newNode[T comparable](par *Node[T], v int64, id T) *Node[T] {
	return &Node[T]{Parent: par,
		Value: v,
		sum:   v,
		count: 1,
		ID:    id,
	}
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

func (n *Node[T]) insert(v int64, id T) *Node[T] {
	if v <= n.Value {
		if n.L == nil {
			n.L = newNode(n, v, id)
		} else {
			n.L = n.L.insert(v, id)
		}
	} else {
		if n.R == nil {
			n.R = newNode(n, v, id)
		} else {
			n.R = n.R.insert(v, id)
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

func (toDelete *Node[T]) deleteNode() *Node[T] {
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

	toReplace := toDelete.R.minNode()

	toDelete.Value = toReplace.Value
	toDelete.ID = toReplace.ID

	toDelete.R = toDelete.R.delete(toReplace.Value, toReplace.ID)

	toDelete.recompute()
	return toDelete.rotate()
}

func (n *Node[T]) delete(v int64, id T) *Node[T] {
	if n == nil {
		return nil
	}
	if v == n.Value && id == n.ID {
		return n.deleteNode()
	} else if v <= n.Value {
		n.L = n.L.delete(v, id)
	} else if v > n.Value {
		n.R = n.R.delete(v, id)
	}

	n.recompute()
	return n.rotate()
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

func (a *AVL[T]) Insert(v int64, id T) {
	if a.root == nil {
		a.root = newNode(nil, v, id)
		return
	}
	if v < 0 {
		panic("negative values are unsupported")
	}
	a.root = a.root.insert(v, id)
}

func (a *AVL[T]) Delete(v int64, id T) {
	if a.root == nil {
		return
	}
	if a.root.Value == v && a.root.ID == id {
		a.root = a.root.deleteNode()
	} else {
		a.root = a.root.delete(v, id)
	}
}

func (a *AVL[T]) Replace(v int64, id T) {
	a.Delete(v, id)
	a.Insert(v, id)
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

func (a AVL[T]) Find(v int64, id T) *Node[T] {
	if a.root == nil {
		return nil
	}
	for n := range a.Range(v, v+1) {
		if n.ID == id {
			return n
		}
	}
	return nil
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
