// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// errListenControl marks an error returned by a listen control function: the
// socket itself was refused, which trying another port does not change.
var errListenControl = errors.New("listen control refused the socket")

// listenConfig returns the net.ListenConfig that runs control on every socket
// before it is bound. A nil control means no control.
func listenConfig(control func(network, address string, c syscall.RawConn) error) *net.ListenConfig {
	lc := &net.ListenConfig{}
	// The run's listener stays a plain TCP socket so the counter's socket
	// storage matches the socket that owns the packets.
	lc.SetMultipathTCP(false)
	if control == nil {
		return lc
	}
	lc.Control = func(network, address string, c syscall.RawConn) error {
		if err := control(network, address, c); err != nil {
			return fmt.Errorf("%w: %w", errListenControl, err)
		}
		return nil
	}
	return lc
}

// ListenTCP binds a TCP listener on the first free port in the pool and returns
// the listener, the bound port, and the public "host:port" address. control,
// when not nil, runs on the socket before it is bound and listening, so a
// setting it applies covers the listener's first handshake reply. It returns an
// error when no free port is available or when control refused the socket; in
// both cases no port is allocated and no socket is left open. The listener is
// dual-stack.
func (s *PortManager) ListenTCP(control func(network, address string, c syscall.RawConn) error) (*net.TCPListener, int, string, error) {
	return s.listenTCP("tcp", control)
}

// ListenTCP4 is ListenTCP bound to IPv4 only, for a run that must not accept
// IPv6 peers: its handshake replies and segments to them would leave untagged.
func (s *PortManager) ListenTCP4(control func(network, address string, c syscall.RawConn) error) (*net.TCPListener, int, string, error) {
	return s.listenTCP("tcp4", control)
}

// PublicHost is the configured public host listeners are advertised under.
func (s *PortManager) PublicHost() string {
	if s == nil {
		return ""
	}
	return s.publicAddr
}

func (s *PortManager) listenTCP(network string, control func(network, address string, c syscall.RawConn) error) (*net.TCPListener, int, string, error) {
	lc := listenConfig(control)
	var lis *net.TCPListener
	port, addr, err := s.allocate(func(p int) (int, error) {
		l, err := lc.Listen(context.Background(), network, net.JoinHostPort("", strconv.Itoa(p)))
		if err != nil {
			return 0, err
		}
		// Double-check the port actually bound is the one requested.
		if got := l.Addr().(*net.TCPAddr).Port; got != p {
			l.Close()
			return 0, fmt.Errorf("bound to port %d, requested %d", got, p)
		}
		lis = l.(*net.TCPListener)
		return p, nil
	})
	if errors.Is(err, errListenControl) {
		return nil, 0, "", fmt.Errorf("TCP listener: %w", err)
	}
	if err != nil {
		return nil, 0, "", fmt.Errorf("no free TCP port available: %w", err)
	}
	return lis, port, addr, nil
}

// ListenUDP binds a UDP socket on the first free port in the pool and returns
// the connection, the bound port, and the public "host:port" address. control,
// when not nil, runs on the socket before it is bound, so a setting it applies
// covers the first datagram. It returns an error when no free port is
// available or when control refused the socket; in both cases no port is
// allocated and no socket is left open. The socket is dual-stack.
func (s *PortManager) ListenUDP(control func(network, address string, c syscall.RawConn) error) (*net.UDPConn, int, string, error) {
	return s.listenUDP("udp", control)
}

// ListenUDP4 is ListenUDP bound to IPv4 only, for a run that must not
// exchange datagrams with IPv6 peers.
func (s *PortManager) ListenUDP4(control func(network, address string, c syscall.RawConn) error) (*net.UDPConn, int, string, error) {
	return s.listenUDP("udp4", control)
}

func (s *PortManager) listenUDP(network string, control func(network, address string, c syscall.RawConn) error) (*net.UDPConn, int, string, error) {
	lc := listenConfig(control)
	var conn *net.UDPConn
	port, addr, err := s.allocate(func(p int) (int, error) {
		l, err := lc.ListenPacket(context.Background(), network, net.JoinHostPort("", strconv.Itoa(p)))
		if err != nil {
			return 0, err
		}
		if got := l.LocalAddr().(*net.UDPAddr).Port; got != p {
			l.Close()
			return 0, fmt.Errorf("bound to port %d, requested %d", got, p)
		}
		conn = l.(*net.UDPConn)
		return p, nil
	})
	if errors.Is(err, errListenControl) {
		return nil, 0, "", fmt.Errorf("UDP listener: %w", err)
	}
	if err != nil {
		return nil, 0, "", fmt.Errorf("no free UDP port available: %w", err)
	}
	return conn, port, addr, nil
}

// allocate finds the first free port in the pool and verifies it can be bound
// via bind (which returns the actually-bound port or an error). On success it
// marks the port used and returns the bound port and its public "host:port"
// address. A bind failure moves on to the next port; a refusal by the listen
// control function stops and is returned, since another port would be refused
// the same way.
func (s *PortManager) allocate(bind func(int) (int, error)) (int, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range s.ports {
		if _, used := s.inUse[p]; used {
			continue
		}
		bound, err := bind(p)
		if errors.Is(err, errListenControl) {
			return 0, "", err
		}
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
