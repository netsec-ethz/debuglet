// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package socket

import (
	"testing"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

// makeTestPath creates a minimal *pan.Path with the given fingerprint.
// The Metadata and other fields are left at zero values.
func makeTestPath(fingerprint pan.PathFingerprint) *pan.Path {
	return &pan.Path{Fingerprint: fingerprint}
}

// TestPathSelectorInitialize verifies that Initialize stores the paths and
// selects the first path.
func TestPathSelectorInitialize(t *testing.T) {
	sel := NewPathSelector()

	paths := []*pan.Path{
		makeTestPath("fp-a"),
		makeTestPath("fp-b"),
	}
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, paths)

	if p := sel.Path(); p == nil {
		t.Fatal("Path() returned nil after Initialize")
	} else if p.Fingerprint != "fp-a" {
		t.Errorf("expected first path (fp-a), got %q", p.Fingerprint)
	}

	all := sel.Paths()
	if len(all) != 2 {
		t.Errorf("Paths() length: want 2, got %d", len(all))
	}
}

// TestPathSelectorEmpty verifies that Path() returns nil when no paths are set.
func TestPathSelectorEmpty(t *testing.T) {
	sel := NewPathSelector()
	if p := sel.Path(); p != nil {
		t.Errorf("expected nil path, got %v", p)
	}
}

// TestPathSelectorForcePath verifies that ForcePath pins the selector to the
// given index, overriding the current selection.
func TestPathSelectorForcePath(t *testing.T) {
	sel := NewPathSelector()
	paths := []*pan.Path{
		makeTestPath("fp-0"),
		makeTestPath("fp-1"),
		makeTestPath("fp-2"),
	}
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, paths)

	sel.ForcePath(2)
	p := sel.Path()
	if p == nil {
		t.Fatal("Path() returned nil after ForcePath")
	}
	if p.Fingerprint != "fp-2" {
		t.Errorf("expected fp-2, got %q", p.Fingerprint)
	}
}

// TestPathSelectorForcePathOutOfRange verifies that an out-of-range forced path
// falls back to the current path rather than panicking.
func TestPathSelectorForcePathOutOfRange(t *testing.T) {
	sel := NewPathSelector()
	paths := []*pan.Path{makeTestPath("fp-0")}
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, paths)

	sel.ForcePath(99) // out of range
	p := sel.Path()
	if p == nil {
		t.Fatal("Path() returned nil for out-of-range forcedPath")
	}
	// Should fall back to current (index 0).
	if p.Fingerprint != "fp-0" {
		t.Errorf("expected fallback to fp-0, got %q", p.Fingerprint)
	}
}

// TestPathSelectorRefreshPreservesCurrent verifies that Refresh retains the
// current fingerprint when the new list has a different order.
func TestPathSelectorRefreshPreservesCurrent(t *testing.T) {
	sel := NewPathSelector()
	old := []*pan.Path{
		makeTestPath("fp-a"),
		makeTestPath("fp-b"),
	}
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, old)

	sel.PathDown("fp-a", pan.PathInterface{})

	refreshed := []*pan.Path{
		makeTestPath("fp-x"),
		makeTestPath("fp-y"),
		makeTestPath("fp-b"),
	}
	sel.Refresh(refreshed)

	p := sel.Path()
	if p == nil || p.Fingerprint != "fp-b" {
		t.Errorf("Refresh: expected fp-b to be preserved, got %v", p)
	}
}

// TestPathSelectorRefreshNewPaths verifies that when the current fingerprint is
// gone, Refresh falls back to index 0.
func TestPathSelectorRefreshNewPaths(t *testing.T) {
	sel := NewPathSelector()
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, []*pan.Path{makeTestPath("fp-old")})

	sel.Refresh([]*pan.Path{
		makeTestPath("fp-new-a"),
		makeTestPath("fp-new-b"),
	})

	p := sel.Path()
	if p == nil || p.Fingerprint != "fp-new-a" {
		t.Errorf("expected fallback to index 0 (fp-new-a), got %v", p)
	}
}

// TestPathSelectorClose verifies that Close is a no-op (returns nil).
func TestPathSelectorClose(t *testing.T) {
	sel := NewPathSelector()
	if err := sel.Close(); err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

func TestPathSelectorPathDown(t *testing.T) {
	failedInterface := pan.PathInterface{IA: 1, IfID: 2}
	shared := &pan.Path{Fingerprint: "shared", Metadata: &pan.PathMetadata{
		Interfaces: []pan.PathInterface{failedInterface},
	}}
	alsoShared := &pan.Path{Fingerprint: "also-shared", Metadata: &pan.PathMetadata{
		Interfaces: []pan.PathInterface{failedInterface},
	}}
	safe := makeTestPath("safe")
	tests := []struct {
		name      string
		paths     []*pan.Path
		failed    pan.PathFingerprint
		iface     pan.PathInterface
		want      *pan.Path
		remaining int
	}{
		{name: "empty", failed: "missing"},
		{name: "current", paths: []*pan.Path{makeTestPath("failed"), shared}, failed: "failed", want: shared, remaining: 1},
		{name: "unrelated", paths: []*pan.Path{shared}, failed: "unrelated", want: shared, remaining: 1},
		{name: "last", paths: []*pan.Path{makeTestPath("failed")}, failed: "failed"},
		{name: "shared interface", paths: []*pan.Path{shared, alsoShared, safe}, failed: "unrelated", iface: failedInterface, want: safe, remaining: 1},
		{name: "other path", paths: []*pan.Path{safe, shared}, failed: "shared", want: safe, remaining: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel := NewPathSelector()
			sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, tt.paths)
			sel.PathDown(tt.failed, tt.iface)
			if got := sel.Path(); got != tt.want {
				t.Fatalf("Path() = %v, want %v", got, tt.want)
			}
			if got := len(sel.Paths()); got != tt.remaining {
				t.Fatalf("Paths() length = %d, want %d", got, tt.remaining)
			}
			// A repeated notification must also be safe after the last path is lost.
			sel.PathDown(tt.failed, tt.iface)
			if got := sel.Path(); got != tt.want {
				t.Fatalf("repeated PathDown changed selection: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPathSelectorPinSurvivesRefreshAndLoss(t *testing.T) {
	sel := NewPathSelector()
	a, b := makeTestPath("a"), makeTestPath("b")
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, []*pan.Path{a, b})
	sel.ForcePath(1)

	refreshed := makeTestPath("b")
	sel.Refresh([]*pan.Path{refreshed, a})
	if got := sel.Path(); got != refreshed {
		t.Fatalf("reordered pin = %v, want refreshed path %v", got, refreshed)
	}

	sel.PathDown("a", pan.PathInterface{})
	if got := sel.Path(); got != refreshed {
		t.Fatalf("unrelated loss changed pin: %v", got)
	}
	sel.Refresh([]*pan.Path{refreshed, a})
	sel.PathDown("b", pan.PathInterface{})
	if got := sel.Path(); got != nil {
		t.Fatalf("lost pin = %v, want nil", got)
	}
	sel.Refresh([]*pan.Path{a})
	if got := sel.Path(); got != nil {
		t.Fatalf("absent pin selected another path: %v", got)
	}
	sel.Refresh([]*pan.Path{a, b})
	if got := sel.Path(); got != b {
		t.Fatalf("restored pin = %v, want %v", got, b)
	}

	sel.Refresh(nil)
	if got := sel.Path(); got != nil {
		t.Fatalf("empty refresh = %v, want nil", got)
	}
	sel.Refresh([]*pan.Path{a})
	sel.ForcePath(-1)
	if got := sel.Path(); got != a {
		t.Fatalf("cleared pin = %v, want %v", got, a)
	}
}

func TestPathSelectorInvalidPinDoesNotSelectFutureIndex(t *testing.T) {
	sel := NewPathSelector()
	a, b := makeTestPath("a"), makeTestPath("b")
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, []*pan.Path{a})
	sel.ForcePath(1)
	sel.Refresh([]*pan.Path{a, b})
	if got := sel.Path(); got != a {
		t.Fatalf("invalid pin selected a later index: got %v, want %v", got, a)
	}
}
