package avl

import (
	"fmt"
	"slices"
	"testing"
)

func TestInsertDelete(t *testing.T) {
	tree := AVL[int]{}
	tree.Insert(1, 1)
	tree.Insert(3, 3)
	tree.Insert(2, 2)
	tree.Insert(4, 4)
	tree.Insert(5, 5)
	tree.Insert(5, 5)
	if tree.root.count != 6 || tree.root.sum != 20 {
		t.Fatalf("Expected count=6, sum=20. Got count=%d, sum=%d", tree.root.count, tree.root.sum)
	}
	tree.Delete(3, 3)
	tree.Delete(5, 5)
	tree.Delete(5, 5)
	if tree.root.count != 3 || tree.root.sum != 7 {
		t.Fatalf("Expected count=3, sum=7. Got count=%d, sum=%d", tree.root.count, tree.root.sum)
	}
}

func TestRange(t *testing.T) {
	tree := AVL[string]{}
	tree.Insert("7", 7)
	tree.Insert("2", 2)
	tree.Insert("9", 9)
	tree.Insert("10", 10)
	tree.Insert("8", 8)
	rng := slices.Collect(tree.Range(3, 9))
	if len(rng) != 2 || rng[0].ID != "7" || rng[1].ID != "8" {
		t.Fatalf("Expected range of [7,8], got %v", rng)
	}
}

func TestUnbounded(t *testing.T) {
	tree := AVL[int]{}
	tree.Insert(7, 7)
	tree.Insert(2, 2)
	tree.Insert(22, 2)
	tree.Insert(9, 9)
	tree.Insert(10, 10)
	tree.Insert(8, 8)
	rng := slices.Collect(tree.Range(3, Unbounded))
	slices.SortFunc(rng, func(a, b *Node[int]) int { return a.ID - b.ID })
	if len(rng) != 4 || rng[0].ID != 7 || rng[1].ID != 8 || rng[2].ID != 9 || rng[3].ID != 10 {
		t.Fatalf("Expected range of [7,8,9,10], got %v", rng)
	}
	rng = slices.Collect(tree.Range(Unbounded, 9))
	slices.SortFunc(rng, func(a, b *Node[int]) int { return a.ID - b.ID })
	if len(rng) != 4 || rng[0].ID != 2 || rng[1].ID != 7 || rng[2].ID != 8 || rng[3].ID != 22 {
		t.Fatalf("Expected range of [2(id=2),2(id=22),7,8], got %v", rng)
	}
}

func TestFind(t *testing.T) {
	tree := AVL[string]{}
	tree.Insert("7", 7)
	tree.Insert("2", 2)
	tree.Insert("9", 9)
	tree.Insert("10", 10)
	tree.Insert("SOLUTION", 8)
	if x := tree.Find(8, "SOLUTION"); x == nil || x.ID != "SOLUTION" {
		t.Fatalf("Expected to find Node with id=\"SOLUTION\", got %v", x)
	}
}

func TestFairshare(t *testing.T) {
	tests := []struct {
		name   string
		values []int64
		cap    int64
		want   int64
	}{
		{name: "given example outputs 266", values: []int64{200, 300, 400, 500}, cap: 1000, want: 266},
		{name: "capacity just below sum returns near max", values: []int64{200, 300, 400, 500}, cap: 1399, want: 499},
		{name: "all values equal", values: []int64{100, 100, 100}, cap: 200, want: 66},
		{name: "single element returns cap when cap below value", values: []int64{500}, cap: 300, want: 300},
		{name: "low capacity uses equal split", values: []int64{200, 300, 400, 500}, cap: 300, want: 75},
		{name: "very low capacity still splits equally", values: []int64{200, 300, 400, 500}, cap: 100, want: 25},
		{name: "duplicates and skewed values", values: []int64{100, 100, 600}, cap: 500, want: 300},
		{name: "capacity just above small values", values: []int64{50, 120, 200}, cap: 260, want: 105},
		{name: "one small value gets fixed then split", values: []int64{10, 20, 30}, cap: 40, want: 15},
		{name: "multiple small values then split", values: []int64{1, 2, 100}, cap: 10, want: 7},
		{name: "all equal with non-divisible capacity", values: []int64{50, 50, 50, 50}, cap: 199, want: 49},
		{name: "empty tree returns zero", values: []int64{}, cap: 1000, want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := AVL[string]{}
			for i, v := range tc.values {
				tree.Insert(fmt.Sprintf("%d-%d", v, i), v)
			}
			if got := tree.Fairshare(tc.cap); got != tc.want {
				t.Fatalf("Expected fairshare=%d, got %d", tc.want, got)
			}
		})
	}
}
