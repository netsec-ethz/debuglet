package wasm

import (
	"math"
	"testing"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

// The path and interface indexes come from the guest. An index outside the
// current path list, a negative one or a path without metadata answers the
// documented "none" value instead of panicking in the host.
func TestSCIONPathIndexesAreBounded(t *testing.T) {
	paths := []*pan.Path{
		{Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{IA: 1, IfID: 11}, {IA: 2, IfID: 12}}}},
		{},
		nil,
	}
	if got := pathHops(paths, 0); got != 1 {
		t.Fatalf("hops of path 0 = %d, want 1", got)
	}
	if ia, ifID := pathInterface(paths, 0, 1); ia != 2 || ifID != 12 {
		t.Fatalf("interface 1 of path 0 = (%d, %d), want (2, 12)", ia, ifID)
	}
	for _, pathIdx := range []int32{-1, 1, 2, 3, math.MaxInt32, math.MinInt32} {
		if got := pathHops(paths, pathIdx); got != -1 {
			t.Errorf("hops of path %d = %d, want -1", pathIdx, got)
		}
		if ia, ifID := pathInterface(paths, pathIdx, 0); ia != 0 || ifID != 0 {
			t.Errorf("interface 0 of path %d = (%d, %d), want zeros", pathIdx, ia, ifID)
		}
	}
	for _, ifIdx := range []int32{-1, 2, math.MaxInt32, math.MinInt32} {
		if ia, ifID := pathInterface(paths, 0, ifIdx); ia != 0 || ifID != 0 {
			t.Errorf("interface %d of path 0 = (%d, %d), want zeros", ifIdx, ia, ifID)
		}
	}
	if got := pathHops(nil, 0); got != -1 {
		t.Errorf("hops with no paths = %d, want -1", got)
	}
}
