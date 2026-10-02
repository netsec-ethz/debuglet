// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"net/netip"
	"strings"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func validConnectivity(c *wire.Connectivity) bool {
	if c == nil {
		return true
	}
	if c.SchemaVersion != 1 || len(c.Disagreements) > 16 {
		return false
	}
	for _, r := range []wire.Reachability{c.IPv4, c.IPv6, c.TCPListener, c.UDPListener, c.SCIONListener, c.SCIONPaths} {
		if len(r.Reason) > 64 || len(r.Endpoint) > 256 || strings.ContainsAny(r.Reason+r.Endpoint, "\r\n") {
			return false
		}
		switch r.State {
		case "untested":
			if r.ObservedAt != nil || r.ExpiresAt != nil || r.Stale || r.Source != "" || r.Address != "" {
				return false
			}
		case "reachable", "unreachable":
			if r.Source != wire.SourceExecutorReported && r.Source != wire.SourceDispatcherObserved {
				return false
			}
			if r.ObservedAt == nil || r.ExpiresAt == nil || *r.ObservedAt <= 0 || *r.ExpiresAt <= *r.ObservedAt {
				return false
			}
		default:
			return false
		}
		if r.Address != "" {
			if _, err := netip.ParseAddr(r.Address); err != nil {
				return false
			}
		}
	}
	h := c.SCIONHost
	if h.Value == nil {
		return h.Source == nil && h.ObservedAt == nil
	}
	_, err := netip.ParseAddr(*h.Value)
	return err == nil && h.Source != nil && *h.Source == wire.SourceExecutorReported && h.ObservedAt != nil && *h.ObservedAt > 0
}
