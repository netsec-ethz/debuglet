package dyn

import (
	"fmt"
	"math"
	"strings"
)

type node struct {
	lc, rc  *node
	t, lazy int64
}

func (n node) String() string {
	left := "<nil>"
	if n.lc != nil {
		left = fmt.Sprintf("%d", n.lc.t)
	}
	right := "<nil>"
	if n.rc != nil {
		right = fmt.Sprintf("%d", n.rc.t)
	}
	return fmt.Sprintf("{%d}[%s, %s]", n.t, left, right)
}

type DynSegTree struct {
	root *node
	L, R int64
}

func New() *DynSegTree {
	return &DynSegTree{
		root: &node{},
		L:    0,
		R:    math.MaxInt,
	}
}

func (d DynSegTree) String() string {
	return d.root.String()
}

func (d DynSegTree) ToDot() string {
	var sb strings.Builder
	sb.WriteString("digraph SegTree {\n")
	sb.WriteString("  node [shape=record];\n")

	if d.root == nil {
		sb.WriteString("}\n")
		return sb.String()
	}

	var traverse func(n *node, l, r, id int64)
	var nextID int64 = 0
	traverse = func(n *node, l, r, id int64) {
		label := fmt.Sprintf("[%d, %d]|val: %d|lazy: %d", l, r, n.t, n.lazy)
		fmt.Fprintf(&sb, "  node%d [label=\"%s\"];\n", id, label)

		mid := l + (r-l)/2

		if n.lc != nil {
			nextID++
			leftID := nextID
			fmt.Fprintf(&sb, "  node%d -> node%d [label=\"L\"];\n", id, leftID)
			traverse(n.lc, l, mid, leftID)
		}

		if n.rc != nil {
			nextID++
			rightID := nextID
			fmt.Fprintf(&sb, "  node%d -> node%d [label=\"R\"];\n", id, rightID)
			traverse(n.rc, mid+1, r, rightID)
		}
	}

	traverse(d.root, d.L, d.R, 0)
	sb.WriteString("}\n")
	return sb.String()
}

func (d *DynSegTree) Total() int64 {
	if d.root == nil {
		return 0
	}
	return d.root.t
}

func (d *DynSegTree) Add(l, r, add int64) {
	d.add(d.root, d.L, d.R, l, r, add)
}

func (d *DynSegTree) add(n *node, tl, tr, l, r, add int64) {
	if n == nil || l > r {
		return
	}
	if l == tl && r == tr {
		n.t += add
		n.lazy += add
		return
	}

	d.push(n, tl, tr)

	tm := tl + (tr-tl)/2
	if n.lc == nil {
		n.lc = &node{}
	}
	if n.rc == nil {
		n.rc = &node{}
	}

	d.add(n.lc, tl, tm, l, min(r, tm), add)
	d.add(n.rc, tm+1, tr, max(l, tm+1), r, add)

	n.t = max(n.lc.t, n.rc.t)
	if n.t == 0 {
		n.lc = nil
		n.rc = nil
	}
}

func (d *DynSegTree) Get(pos int64) int64 {
	return d.get(d.root, d.L, d.R, pos)
}

func (d *DynSegTree) get(n *node, tl, tr, pos int64) int64 {
	if n == nil || n.t == 0 {
		return 0
	}
	if tl == tr {
		return n.t
	}
	d.push(n, tl, tr)
	tm := tl + (tr-tl)/2
	if pos <= tm {
		return d.get(n.lc, tl, tm, pos)
	} else {
		return d.get(n.rc, tm+1, tr, pos)
	}
}

func (d *DynSegTree) QueryMax(l, r int64) int64 {
	return d.querymax(d.root, d.L, d.R, l, r)
}

func (d *DynSegTree) querymax(n *node, tl, tr, l, r int64) int64 {
	if n == nil || l > r {
		return 0
	}
	if l <= tl && tr <= r {
		return n.t
	}

	d.push(n, tl, tr)
	tm := tl + (tr-tl)/2
	leftMax := d.querymax(n.lc, tl, tm, l, min(r, tm))
	rightMax := d.querymax(n.rc, tm+1, tr, max(l, tm+1), r)
	return max(leftMax, rightMax)
}

func (d *DynSegTree) push(n *node, tl, tr int64) {
	if n.lazy == 0 || tl == tr {
		return
	}
	if n.lc == nil {
		n.lc = &node{}
	}
	if n.rc == nil {
		n.rc = &node{}
	}

	n.lc.t += n.lazy
	n.lc.lazy += n.lazy
	n.rc.t += n.lazy
	n.rc.lazy += n.lazy
	n.lazy = 0
}
