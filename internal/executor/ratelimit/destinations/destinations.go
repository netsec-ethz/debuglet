// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package destinations holds the bookkeeping both packet counters keep to apply
// a per-destination limit given by name: which resolved addresses each
// debuglet's connections to that name reached.
package destinations

import (
	"iter"
	"net/netip"

	"github.com/google/uuid"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
)

type key struct {
	addr string
	id   uuid.UUID
}

// Resolved counts, for each debuglet and the destination address it asked for,
// the live attachments to each IP that address resolved to. The zero value is
// ready to use. It does no locking of its own: the packet counter that owns it
// holds its lock around every call.
type Resolved struct {
	byAddr map[key]map[netutil.IPv6]int
}

// Add records one more attachment of debuglet id, which asked for addr, to ip.
func (r *Resolved) Add(addr string, id uuid.UUID, ip netutil.IPv6) {
	if r.byAddr == nil {
		r.byAddr = make(map[key]map[netutil.IPv6]int)
	}
	k := key{addr, id}
	ips, ok := r.byAddr[k]
	if !ok {
		ips = make(map[netutil.IPv6]int)
		r.byAddr[k] = ips
	}
	ips[ip]++
}

// Targets yields the IPs a limit that debuglet id sets on addr applies to: addr
// itself when it is an IP literal, otherwise every IP its attachments to addr
// currently reach. The caller must not call Add or Remove while iterating.
func (r *Resolved) Targets(addr string, id uuid.UUID) iter.Seq[netutil.IPv6] {
	return func(yield func(netutil.IPv6) bool) {
		if ip, err := netip.ParseAddr(addr); err == nil {
			yield(netutil.ToIPv6(ip))
			return
		}
		for ip := range r.byAddr[key{addr, id}] {
			if !yield(ip) {
				return
			}
		}
	}
}

// Remove drops one attachment recorded by Add. It reports how many attachments
// of debuglet id through addr to ip remain, and false when there was none to
// drop, in which case nothing changes.
func (r *Resolved) Remove(addr string, id uuid.UUID, ip netutil.IPv6) (remaining int, ok bool) {
	k := key{addr, id}
	ips := r.byAddr[k]
	attachments := ips[ip]
	if attachments <= 0 {
		return 0, false
	}
	if attachments == 1 {
		delete(ips, ip)
	} else {
		ips[ip] = attachments - 1
	}
	if len(ips) == 0 {
		delete(r.byAddr, k)
	}
	return attachments - 1, true
}
