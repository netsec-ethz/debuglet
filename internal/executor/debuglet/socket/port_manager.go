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

// PortManager hands out listener ports from a pre-configured pool, shared
// across protocols (TCP and UDP). One unused port is allocated per listening
// debuglet and released on close; a port allocated to one protocol can never be
// handed out to the other because both share the same inUse map.
// It is intentionally dependency-free (plain string args) so it does not
// introduce import cycles between the config and executor packages.
type PortManager struct {
	mu         sync.Mutex
	publicAddr string
	ports      []int
	inUse      map[int]struct{}
}

// NewPortManager parses portsSpec and returns a ready-to-use PortManager.
func NewPortManager(publicAddr, portsSpec string) (*PortManager, error) {
	ports, err := ParsePortRanges(portsSpec)
	if err != nil {
		return nil, err
	}
	return &PortManager{
		publicAddr: publicAddr,
		ports:      ports,
		inUse:      make(map[int]struct{}),
	}, nil
}

// Enabled reports whether listening is configured and available.
func (s *PortManager) Enabled() bool {
	return s != nil && s.publicAddr != "" && len(s.ports) > 0
}

// ListenTCP binds a TCP listener on the first free port in the pool and returns
// the listener, the bound port, and the public "host:port" address. It returns
// an error when no free port is available.
func (s *PortManager) ListenTCP() (*net.TCPListener, int, string, error) {
	var lis *net.TCPListener
	port, addr, err := s.allocate(func(p int) (int, error) {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: p})
		if err != nil {
			return 0, err
		}
		// Double-check the port actually bound is the one requested.
		if got := l.Addr().(*net.TCPAddr).Port; got != p {
			l.Close()
			return 0, fmt.Errorf("bound to port %d, requested %d", got, p)
		}
		lis = l
		return p, nil
	})
	if err != nil {
		return nil, 0, "", fmt.Errorf("no free TCP port available: %w", err)
	}
	return lis, port, addr, nil
}

// ListenUDP binds a UDP socket on the first free port in the pool and returns
// the connection, the bound port, and the public "host:port" address. It
// returns an error when no free port is available.
func (s *PortManager) ListenUDP() (*net.UDPConn, int, string, error) {
	var conn *net.UDPConn
	port, addr, err := s.allocate(func(p int) (int, error) {
		l, err := net.ListenUDP("udp", &net.UDPAddr{Port: p})
		if err != nil {
			return 0, err
		}
		if got := l.LocalAddr().(*net.UDPAddr).Port; got != p {
			l.Close()
			return 0, fmt.Errorf("bound to port %d, requested %d", got, p)
		}
		conn = l
		return p, nil
	})
	if err != nil {
		return nil, 0, "", fmt.Errorf("no free UDP port available: %w", err)
	}
	return conn, port, addr, nil
}

// allocate finds the first free port in the pool and verifies it can be bound
// via bind (which returns the actually-bound port or an error). On success it
// marks the port used and returns the bound port and its public "host:port"
// address.
func (s *PortManager) allocate(bind func(int) (int, error)) (int, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range s.ports {
		if _, used := s.inUse[p]; used {
			continue
		}
		bound, err := bind(p)
		if err != nil {
			continue // EADDRINUSE etc → try next
		}
		if bound != p {
			continue
		}
		s.inUse[p] = struct{}{}
		return p, net.JoinHostPort(s.publicAddr, strconv.Itoa(p)), nil
	}
	return 0, "", fmt.Errorf("no free port available")
}

// Release returns a previously allocated port back to the pool.
func (s *PortManager) Release(port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inUse, port)
}
