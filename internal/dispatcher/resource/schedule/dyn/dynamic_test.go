package dyn

import (
	"math"
	"math/rand"
	"testing"
)

// Helper naive range array for differential testing (oracle)
type naiveArray struct {
	data map[int]int64
}

func newNaiveArray() *naiveArray {
	return &naiveArray{data: make(map[int]int64)}
}

func (a *naiveArray) Add(l, r, add int64) {
	for i := l; i <= r; i++ {
		a.data[int(i)] += add
	}
}

func (a *naiveArray) Get(pos int64) int64 {
	return a.data[int(pos)]
}

func (a *naiveArray) QueryMax(l, r int64) int64 {
	var maxVal int64 = 0
	for i := l; i <= r; i++ {
		if a.data[int(i)] > maxVal {
			maxVal = a.data[int(i)]
		}
	}
	return maxVal
}

// 1. Basic Single Point and Small Range Updates
func TestBasicAddAndGet(t *testing.T) {
	tree := New()

	tree.Add(5, 5, 10)
	if got := tree.Get(5); got != 10 {
		t.Errorf("Get(5) = %d; want 10", got)
	}
	if got := tree.Get(4); got != 0 {
		t.Errorf("Get(4) = %d; want 0", got)
	}

	tree.Add(2, 6, 5)
	// Expected state: pos 5 -> 15; pos 2..4,6 -> 5; others -> 0
	tests := []struct {
		pos  int64
		want int64
	}{
		{1, 0},
		{2, 5},
		{5, 15},
		{6, 5},
		{7, 0},
	}

	for _, tc := range tests {
		if got := tree.Get(tc.pos); got != tc.want {
			t.Errorf("Get(%d) = %d; want %d", tc.pos, got, tc.want)
		}
	}
}

// 2. QueryMax Correctness
func TestQueryMax(t *testing.T) {
	tree := New()

	tree.Add(10, 20, 3)
	tree.Add(15, 25, 4)

	// Intervals: [10, 14] -> 3, [15, 20] -> 7, [21, 25] -> 4
	tests := []struct {
		l, r int64
		want int64
	}{
		{0, 9, 0},
		{10, 14, 3},
		{12, 18, 7},
		{21, 25, 4},
		{0, 100, 7},
	}

	for _, tc := range tests {
		if got := tree.QueryMax(tc.l, tc.r); got != tc.want {
			t.Errorf("QueryMax(%d, %d) = %d; want %d", tc.l, tc.r, got, tc.want)
		}
	}
}

// 3. Large / Sparse Coordinates (Tests overflow & high coordinate support)
func TestLargeCoordinates(t *testing.T) {
	tree := New()

	const highPos1 = 1_000_000_000
	const highPos2 = 2_000_000_000

	tree.Add(highPos1, highPos1+100, 42)
	tree.Add(highPos2, highPos2+50, 100)

	if got := tree.Get(highPos1 + 10); got != 42 {
		t.Errorf("Get(%d) = %d; want 42", highPos1+10, got)
	}

	if got := tree.Get(highPos2 + 25); got != 100 {
		t.Errorf("Get(%d) = %d; want 100", highPos2+25, got)
	}

	if got := tree.QueryMax(0, math.MaxInt-1); got != 100 {
		t.Errorf("QueryMax over large range = %d; want 100", got)
	}
}

// 4. Lazy Propagation Verification
func TestLazyPropagationPartialOverlap(t *testing.T) {
	tree := New()

	// Apply wide range update
	tree.Add(0, 100, 10)

	// Partial query that forces lazy push down
	if got := tree.QueryMax(10, 20); got != 10 {
		t.Errorf("QueryMax(10, 20) = %d; want 10", got)
	}

	// Apply partial update on subsegment
	tree.Add(15, 15, 5)

	if got := tree.Get(15); got != 15 {
		t.Errorf("Get(15) = %d; want 15", got)
	}
	if got := tree.Get(14); got != 10 {
		t.Errorf("Get(14) = %d; want 10", got)
	}
}

// 5. Random Fuzz / Differential Testing against Naive Oracle
func TestFuzzAgainstNaive(t *testing.T) {
	tree := New()
	oracle := newNaiveArray()

	rng := rand.New(rand.NewSource(42))
	const maxCoord = 500
	const operations = 1000

	for i := range operations {
		op := rng.Intn(3)
		l := int64(rng.Intn(maxCoord))
		r := l + rng.Int63n(maxCoord-l+1)

		switch op {
		case 0: // Add
			addVal := rng.Int63n(50) + 1
			tree.Add(l, r, addVal)
			oracle.Add(l, r, addVal)
		case 1: // Get point
			pos := l
			got := tree.Get(pos)
			want := oracle.Get(pos)
			if got != want {
				t.Fatalf("Op %d [Get]: at pos %d got %d, want %d", i, pos, got, want)
			}
		case 2: // QueryMax
			got := tree.QueryMax(l, r)
			want := oracle.QueryMax(l, r)
			if got != want {
				t.Fatalf("Op %d [QueryMax]: range [%d, %d] got %d, want %d", i, l, r, got, want)
			}
		}
	}
}

func TestAddAndSubtractRanges(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "Basic Range Add and Subtract",
			fn: func(t *testing.T) {
				st := New()
				st.Add(10, 20, 5)

				if got := st.QueryMax(10, 20); got != 5 {
					t.Errorf("expected max 5 after add, got %d", got)
				}
				if got := st.Get(15); got != 5 {
					t.Errorf("expected val 5 at pos 15, got %d", got)
				}

				// Subtract range back
				st.Add(10, 20, -5)

				if got := st.QueryMax(10, 20); got != 0 {
					t.Errorf("expected max 0 after subtract, got %d", got)
				}
				if got := st.Get(15); got != 0 {
					t.Errorf("expected val 0 at pos 15, got %d", got)
				}
			},
		},
		{
			name: "Overlapping Range Addition and Subtraction",
			fn: func(t *testing.T) {
				st := New()
				st.Add(5, 15, 10)
				st.Add(10, 20, 5)

				if got := st.Get(12); got != 15 {
					t.Errorf("expected pos 12 to be 15, got %d", got)
				}
				if got := st.QueryMax(0, 30); got != 15 {
					t.Errorf("expected max to be 15, got %d", got)
				}

				st.Add(5, 15, -10)

				if got := st.Get(12); got != 5 {
					t.Errorf("expected pos 12 to be 5 after partial subtract, got %d", got)
				}
				if got := st.Get(8); got != 0 {
					t.Errorf("expected pos 8 to be 0 after full subtract, got %d", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.fn)
	}
}
