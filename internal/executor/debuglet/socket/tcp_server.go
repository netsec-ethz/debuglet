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
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ParsePortRanges expands "2022,2025-3005,56000-62000" into a deduped,
// ordered []int. Each port must satisfy 1 <= p <= 65535 and range start <= end.
// Empty string yields an empty list with no error.
func ParsePortRanges(spec string) ([]int, error) {
	if strings.TrimSpace(spec) == "" {
		return []int{}, nil
	}

	seen := make(map[int]struct{})
	var ports []int
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, err := parseRange(part)
		if err != nil {
			return nil, err
		}
		for p := lo; p <= hi; p++ {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports, nil
}

func parseRange(part string) (int, int, error) {
	fields := strings.SplitN(part, "-", 2)
	lo, err := parsePort(fields[0])
	if err != nil {
		return 0, 0, err
	}
	hi := lo
	if len(fields) == 2 {
		hi, err = parsePort(fields[1])
		if err != nil {
			return 0, 0, err
		}
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("invalid port range %q: start %d greater than end %d", part, lo, hi)
	}
	return lo, hi, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %d: must be between 1 and 65535", p)
	}
	return p, nil
}

// TCPServerManager hands out TCP listener ports from a pre-configured pool. One
// unused port is allocated per listening debuglet and released on close.
// It is intentionally dependency-free (plain string args) so it does not
// introduce import cycles between the config and executor packages.
type TCPServerManager struct {
	mu         sync.Mutex
	publicAddr string
	ports      []int
	inUse      map[int]struct{}
}

// NewTCPServer parses portsSpec and returns a ready-to-use TCPServer.
func NewTCPServer(publicAddr, portsSpec string) (*TCPServerManager, error) {
	ports, err := ParsePortRanges(portsSpec)
	if err != nil {
		return nil, err
	}
	return &TCPServerManager{
		publicAddr: publicAddr,
		ports:      ports,
		inUse:      make(map[int]struct{}),
	}, nil
}

// Enabled reports whether TCP listening is configured and available.
func (s *TCPServerManager) Enabled() bool {
	return s != nil && s.publicAddr != "" && len(s.ports) > 0
}

// Listen binds a TCP listener on the first free port in the pool and returns
// the listener, the bound port, and the public "host:port" address. It returns
// an error when no free port is available.
func (s *TCPServerManager) Listen() (*net.TCPListener, int, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range s.ports {
		if _, used := s.inUse[p]; used {
			continue
		}
		l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: p})
		if err != nil {
			continue // EADDRINUSE etc → try next
		}
		// Double-check the port actually bound is the one requested.
		if got := l.Addr().(*net.TCPAddr).Port; got != p {
			l.Close()
			continue
		}
		s.inUse[p] = struct{}{}
		return l, p, net.JoinHostPort(s.publicAddr, strconv.Itoa(p)), nil
	}
	return nil, 0, "", fmt.Errorf("no free TCP port available")
}

// Release returns a previously allocated port back to the pool.
func (s *TCPServerManager) Release(port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inUse, port)
}
