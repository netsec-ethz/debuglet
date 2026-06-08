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

package engine

import (
	"fmt"
	"sync"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

// PathSelector implements pan.Selector and provides the WASM module with
// control over which SCION path is used for a given connection.
// It replaces the former DebugletSelector.
type PathSelector struct {
	mu      sync.Mutex
	paths   []*pan.Path
	current int

	// forcedPath holds a path index pinned by ForcePath, or -1 if not forced.
	forcedPath int
}

func NewPathSelector() *PathSelector {
	return &PathSelector{forcedPath: -1}
}

// ForcePath pins the selector to the path at index i.
func (s *PathSelector) ForcePath(i int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forcedPath = i
}

// Path returns the currently selected SCION path.
func (s *PathSelector) Path() *pan.Path {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.paths) == 0 {
		return nil
	}
	if s.forcedPath >= 0 && s.forcedPath < len(s.paths) {
		return s.paths[s.forcedPath]
	}
	return s.paths[s.current]
}

// Paths returns a snapshot of all known paths.
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
	s.paths = paths
	s.current = 0
}

func (s *PathSelector) Refresh(paths []*pan.Path) {
	s.mu.Lock()
	defer s.mu.Unlock()

	newCurrent := 0
	if len(s.paths) > 0 {
		currentFingerprint := s.paths[s.current].Fingerprint
		for i, p := range paths {
			if p.Fingerprint == currentFingerprint {
				newCurrent = i
				break
			}
		}
	}
	s.paths = paths
	s.current = newCurrent
}

func (s *PathSelector) PathDown(pf pan.PathFingerprint, pi pan.PathInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.paths[s.current]
	if isInterfaceOnPath(current, pi) || pf == current.Fingerprint {
		fmt.Println("path down:", s.current, len(s.paths))
		// TODO: implement automatic failover to next alive path
	}
}

func (s *PathSelector) Close() error {
	return nil
}

// isInterfaceOnPath reports whether the given interface is on the path.
func isInterfaceOnPath(p *pan.Path, pi pan.PathInterface) bool {
	for _, c := range p.Metadata.Interfaces {
		if c == pi {
			return true
		}
	}
	return false
}
