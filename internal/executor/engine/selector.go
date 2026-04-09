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

type DebugletSelector struct {
	mutex   sync.Mutex
	paths   []*pan.Path
	current int

	forcedPath int
}

func NewDebugletSelector() *DebugletSelector {
	return &DebugletSelector{forcedPath: -1}
}

func (s *DebugletSelector) ForcePath(i int) {
	s.forcedPath = i
}

func (s *DebugletSelector) Path() *pan.Path {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.paths) == 0 {
		return nil
	}

	//fmt.Printf("pan.Path offsets: current %d forced %d\n", s.current, s.forcedPath)

	if s.forcedPath >= 0 && len(s.paths) > s.forcedPath {
		//	fmt.Printf("returning forced path %s\n", s.paths[s.forcedPath].String())

		return s.paths[s.forcedPath]
	}

	//fmt.Printf("returning path %s\n", s.paths[s.current].String())

	return s.paths[s.current]
}

func (s *DebugletSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.paths = paths
	s.current = 0
}

func (s *DebugletSelector) Refresh(paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	newcurrent := 0
	if len(s.paths) > 0 {
		currentFingerprint := s.paths[s.current].Fingerprint
		for i, p := range paths {
			if p.Fingerprint == currentFingerprint {
				newcurrent = i
				break
			}
		}
	}
	s.paths = paths
	s.current = newcurrent
}

func (s *DebugletSelector) PathDown(pf pan.PathFingerprint, pi pan.PathInterface) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	current := s.paths[s.current]
	if isInterfaceOnPath(current, pi) || pf == current.Fingerprint {
		fmt.Println("down:", s.current, len(s.paths))

		//TODO fix path updating

		//better := stats.FirstMoreAlive(current, s.paths)
		//if better >= 0 {
		//	// Try next path. Note that this will keep cycling if we get down notifications
		//	s.current = better
		//	fmt.Println("failover:", s.current, len(s.paths))
		//}
	}
}

func (s *DebugletSelector) Close() error {
	return nil
}

func isInterfaceOnPath(p *pan.Path, pi pan.PathInterface) bool {
	for _, c := range p.Metadata.Interfaces {
		if c == pi {
			return true
		}
	}
	return false
}
