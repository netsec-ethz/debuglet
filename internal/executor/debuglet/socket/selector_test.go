// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
// resets current to zero.
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
// current index when the same fingerprint is present in the new list.
func TestPathSelectorRefreshPreservesCurrent(t *testing.T) {
	sel := NewPathSelector()
	old := []*pan.Path{
		makeTestPath("fp-a"),
		makeTestPath("fp-b"),
	}
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, old)

	// Manually bump current to "fp-b" by forcing it.
	sel.ForcePath(1)
	// Clear the force so Refresh logic is exercised.
	sel.mu.Lock()
	sel.current = 1
	sel.forcedPath = -1
	sel.mu.Unlock()

	refreshed := []*pan.Path{
		makeTestPath("fp-x"),
		makeTestPath("fp-b"), // same fingerprint, different position 1
		makeTestPath("fp-y"),
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
