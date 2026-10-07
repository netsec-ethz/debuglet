// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netpolicy

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
)

// Egress is one immutable dispatcher grant. All of a run's sockets share it.
// It charges admitted payloads and socket connection attempts, not wire packets.
type Egress struct {
	err              error
	deadline         time.Time
	expired          bool
	mu               sync.Mutex
	grant            *pb.EgressGrant
	addresses        map[netip.Addr]struct{}
	bytes, attempts  int64
	writes, connects *rate.Limiter
}

func ValidateEgressGrant(g *pb.EgressGrant) error {
	if g == nil {
		return nil
	}
	if g.Version != 1 || g.BitsPerSecond < 1 || g.BitsPerSecond > 1<<40 ||
		g.BurstBytes < 1 || g.BurstBytes > 16<<20 || g.Bytes < 1 || g.Bytes > 1<<50 ||
		g.AttemptsPerSecond < 1 || g.AttemptsPerSecond > 1_000_000 ||
		g.AttemptBurst < 1 || g.AttemptBurst > 1_000_000 || g.Attempts < 1 || g.Attempts > 1_000_000 ||
		g.NotBeforeUnix < 0 || g.ExpiresUnix <= g.NotBeforeUnix || g.ExpiresUnix-g.NotBeforeUnix > 86400 ||
		len(g.Addresses) == 0 || len(g.Addresses) > 256 {
		return fmt.Errorf("%w: invalid aggregate egress grant", ErrDenied)
	}
	seen := make(map[netip.Addr]bool)
	for _, text := range g.Addresses {
		address, err := netip.ParseAddr(text)
		if err != nil || Normalize(address).String() != text || seen[address] {
			return fmt.Errorf("%w: invalid pinned egress address", ErrDenied)
		}
		seen[address] = true
	}
	return nil
}

func NewEgress(g *pb.EgressGrant) *Egress {
	if g == nil {
		return nil
	}
	if err := ValidateEgressGrant(g); err != nil {
		return &Egress{err: err}
	}
	g = proto.Clone(g).(*pb.EgressGrant)
	now := time.Now()
	e := &Egress{grant: g, deadline: now.Add(time.Unix(g.ExpiresUnix, 0).Sub(now)), addresses: make(map[netip.Addr]struct{}),
		writes:   rate.NewLimiter(rate.Limit(g.BitsPerSecond)/8, int(g.BurstBytes)),
		connects: rate.NewLimiter(rate.Limit(g.AttemptsPerSecond), int(g.AttemptBurst))}
	for _, text := range g.Addresses {
		e.addresses[netip.MustParseAddr(text)] = struct{}{}
	}
	return e
}

func (e *Egress) active() error { return e.activeAt(time.Now()) }

func (e *Egress) activeAt(now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	// The deadline retains monotonic time. Once expired, wall-clock changes
	// cannot reactivate this run's authority.
	if !now.Before(e.deadline) || now.Unix() >= e.grant.ExpiresUnix {
		e.expired = true
	}
	if e.expired || now.Unix() < e.grant.NotBeforeUnix {
		return fmt.Errorf("%w: aggregate egress grant is outside its window", ErrDenied)
	}
	return nil
}

func (e *Egress) CheckAddress(address netip.Addr) error {
	if e == nil {
		return nil
	}
	if err := e.active(); err != nil {
		return err
	}
	if _, ok := e.addresses[Normalize(address)]; !ok {
		return fmt.Errorf("%w: address was not reserved in the aggregate egress grant", ErrDenied)
	}
	return nil
}

// Connect charges each actual outgoing socket attempt, including failed connects.
func (e *Egress) Connect(address netip.Addr) error {
	if e == nil {
		return nil
	}
	if err := e.CheckAddress(address); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.attempts >= e.grant.Attempts || !e.connects.Allow() {
		return fmt.Errorf("%w: aggregate connection-attempt allowance exhausted", ErrDenied)
	}
	e.attempts++
	return nil
}

// Charge reserves the whole attempted write. Short/failed writes are deliberately
// not refunded, so cancellation cannot create additional authority.
func (e *Egress) Charge(n int) error {
	if e == nil || n == 0 {
		return nil
	}
	if err := e.active(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if n < 0 || int64(n) > e.grant.Bytes-e.bytes || !e.writes.AllowN(time.Now(), n) {
		return fmt.Errorf("%w: aggregate payload allowance or rate burst exhausted", ErrDenied)
	}
	e.bytes += int64(n)
	return nil
}

// Wrap applies the grant after the packet counter has attached its socket.
func (e *Egress) Wrap(conn net.Conn) net.Conn {
	if e == nil {
		return conn
	}
	return &egressConn{Conn: conn, egress: e}
}

type egressConn struct {
	net.Conn
	egress *Egress
}

func (c *egressConn) Write(data []byte) (int, error) {
	if err := c.egress.Charge(len(data)); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}

// MatchesPrefix applies the same embedded-address aliases as destination policy.
func MatchesPrefix(prefix netip.Prefix, address netip.Addr) bool {
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	for _, alias := range aliases(address) {
		if prefix.Contains(alias) {
			return true
		}
	}
	return false
}
