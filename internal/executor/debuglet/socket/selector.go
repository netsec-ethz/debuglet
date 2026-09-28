// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package socket

import (
	"sync"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

// PathSelector implements pan.Selector and provides the WASM module with
// control over which SCION path is used for a given connection.
// Automatic selection fails over to the first remaining path. Explicit pins
// stay bound to their fingerprint and return no path while that path is absent.
type PathSelector struct {
	mu      sync.Mutex
	paths   []*pan.Path
	current *pan.Path

	// forcedPath retains the requested fingerprint even while the path is absent.
	forcedPath *pan.Path
}

func NewPathSelector() *PathSelector {
	return &PathSelector{}
}

// ForcePath pins the selector to the path at index i. An invalid index clears
// the pin and resumes automatic selection.
func (s *PathSelector) ForcePath(i int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forcedPath = nil
	if i >= 0 && i < len(s.paths) {
		s.forcedPath = s.paths[i]
	}
	s.refresh(s.paths)
}

// Path returns the currently selected SCION path.
func (s *PathSelector) Path() *pan.Path {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.current
}

// Paths returns a snapshot of the available paths, excluding reported failures.
func (s *PathSelector) Paths() []*pan.Path {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := make([]*pan.Path, len(s.paths))
	copy(snapshot, s.paths)
	return snapshot
}

func (s *PathSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = nil
	s.forcedPath = nil
	s.refresh(paths)
}

// Refresh replaces the available paths. A still-present selection survives a
// reorder; a missing automatic selection falls back to the first path. A pin
// remains unavailable until its fingerprint reappears or ForcePath changes it.
func (s *PathSelector) Refresh(paths []*pan.Path) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh(paths)
}

func (s *PathSelector) refresh(paths []*pan.Path) {
	wanted := s.current
	if s.forcedPath != nil {
		wanted = s.forcedPath
	}
	s.paths = paths
	s.current = nil
	for _, p := range paths {
		if wanted != nil && p.Fingerprint == wanted.Fingerprint {
			s.current = p
			return
		}
	}
	if s.forcedPath == nil && len(paths) > 0 {
		s.current = paths[0]
	}
}

// PathDown removes every path affected by the fingerprint or interface until
// Refresh supplies it again. A lost pin does not silently select another path.
func (s *PathSelector) PathDown(pf pan.PathFingerprint, pi pan.PathInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()

	remaining := make([]*pan.Path, 0, len(s.paths))
	for _, p := range s.paths {
		if p.Fingerprint != pf && !isInterfaceOnPath(p, pi) {
			remaining = append(remaining, p)
		}
	}
	s.refresh(remaining)
}

func (s *PathSelector) Close() error {
	return nil
}

// isInterfaceOnPath reports whether the given interface is on the path.
func isInterfaceOnPath(p *pan.Path, pi pan.PathInterface) bool {
	if p.Metadata == nil {
		return false
	}
	for _, c := range p.Metadata.Interfaces {
		if c == pi {
			return true
		}
	}
	return false
}
