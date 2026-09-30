// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// ExecutorFilter requires every specified observation. Unknown capabilities do
// not match requested filters. Capacity is advertised total bandwidth, not a
// reservation or a promise that a particular run can be admitted.
type ExecutorFilter struct {
	AddressFamilies    []string // ipv4 or ipv6 with a fresh successful controlled observation.
	ReachableListeners []string // tcp, udp or scion; declared support alone is not a match.
	Protocols          []string
	EnforcementMode    string
	MinCapacityBPS     *int64
	// ISDAS requires the executor-reported SCION ISD-AS, such as 1-ff00:0:110.
	// Equivalent spellings match; an unknown ISD-AS does not.
	ISDAS string
	// ASN matches dispatcher-observed control or advertised-host origin. The
	// separate, unverified hello claim never adds a match. Country matches display location.
	ASN     uint32
	Country string
}

func (f ExecutorFilter) Empty() bool {
	return len(f.AddressFamilies) == 0 && len(f.ReachableListeners) == 0 && len(f.Protocols) == 0 && f.EnforcementMode == "" && f.MinCapacityBPS == nil && f.ISDAS == "" && f.ASN == 0 && f.Country == ""
}

func (f ExecutorFilter) capabilityEmpty() bool {
	return len(f.Protocols) == 0 && f.EnforcementMode == "" && f.MinCapacityBPS == nil
}

func (f ExecutorFilter) Validate() error {
	for _, family := range f.AddressFamilies {
		if family != "ipv4" && family != "ipv6" {
			return errors.New("address-family filter must be ipv4 or ipv6")
		}
	}
	for _, listener := range f.ReachableListeners {
		if listener != "tcp" && listener != "udp" && listener != "scion" {
			return errors.New("reachable-listener filter must be tcp, udp or scion")
		}
	}
	for _, protocol := range f.Protocols {
		switch protocol {
		case "tcp", "tls", "udp", "icmp", "scion":
		default:
			return fmt.Errorf("unsupported protocol filter %q: use tcp, tls, udp, icmp or scion", protocol)
		}
	}
	if f.EnforcementMode != "" && f.EnforcementMode != "ebpf" && f.EnforcementMode != "fallback" {
		return errors.New("enforcement filter must be ebpf or fallback")
	}
	if f.MinCapacityBPS != nil && *f.MinCapacityBPS < 0 {
		return errors.New("minimum capacity must not be negative")
	}
	if _, ok := wire.CanonicalISDAS(f.ISDAS); f.ISDAS != "" && !ok {
		return fmt.Errorf("ISD-AS filter %q must be a concrete SCION ISD-AS such as 1-ff00:0:110", f.ISDAS)
	}
	if f.Country != "" && (len(f.Country) != 2 || f.Country[0] < 'A' || f.Country[0] > 'Z' || f.Country[1] < 'A' || f.Country[1] > 'Z') {
		return errors.New("country filter must be an upper-case two-letter country code")
	}
	return nil
}

// DiscoverExecutors fetches a fresh dispatcher snapshot and returns only ready
// matches. The dispatcher excludes dead bindings and expires capability reports.
// Discovery does not hold a reservation; normal submission remains authoritative.
func (c *Client) DiscoverExecutors(ctx context.Context, filter ExecutorFilter) ([]Node, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	matched := []Node{}
	for _, node := range nodes {
		if !node.Ready || node.Admission == wire.AdmissionMaintenance || node.Admission == wire.AdmissionOffline || strings.TrimSpace(node.ID) == "" {
			continue
		}
		if !matchesConnectivity(node.Connectivity, filter, time.Now()) {
			continue
		}
		if filter.ISDAS != "" {
			want, _ := wire.CanonicalISDAS(filter.ISDAS)
			got := node.SCIONISDAS.Value
			if got == nil {
				continue
			}
			if canonical, ok := wire.CanonicalISDAS(*got); !ok || canonical != want {
				continue
			}
		}
		_, country := node.Location()
		if filter.Country != "" && (country.Value == nil || *country.Value != filter.Country) {
			continue
		}
		if filter.ASN != 0 {
			m := node.IPMetadata
			if m == nil || !matchesASN(m.Observed.ASN, filter.ASN) && !matchesASN(m.Advertised.ASN, filter.ASN) {
				continue
			}
		}
		if filter.capabilityEmpty() {
			matched = append(matched, node)
			continue
		}
		capability := node.Capabilities
		if capability == nil || capability.SchemaVersion != 1 {
			continue
		}
		if filter.EnforcementMode != "" && capability.EnforcementMode != filter.EnforcementMode {
			continue
		}
		if filter.MinCapacityBPS != nil && (capability.AdvertisedCapacityBPS == nil || *capability.AdvertisedCapacityBPS < *filter.MinCapacityBPS) {
			continue
		}
		if !slices.ContainsFunc(filter.Protocols, func(protocol string) bool { return !slices.Contains(capability.Protocols, protocol) }) {
			matched = append(matched, node)
		}
	}
	return matched, nil
}

// ErrNoMatchingExecutor reports that no ready executor satisfies a selection.
var ErrNoMatchingExecutor = errors.New("no ready executor matches; check dbl nodes and the requested capability filters")

// SelectExecutor returns one ready match, optionally restricted to an explicit
// ID. Zero or ambiguous matches are errors. This method never submits work.
func (c *Client) SelectExecutor(ctx context.Context, id string, filter ExecutorFilter) (Node, error) {
	nodes, err := c.DiscoverExecutors(ctx, filter)
	if err != nil {
		return Node{}, err
	}
	var selected *Node
	for i := range nodes {
		if id != "" && nodes[i].ID != id {
			continue
		}
		if selected != nil {
			return Node{}, errors.New("more than one ready executor matches; use dbl nodes and choose --executor ID")
		}
		selected = &nodes[i]
	}
	if selected == nil {
		return Node{}, ErrNoMatchingExecutor
	}
	return *selected, nil
}

func matchesASN(r wire.IPLookup[wire.ASInfo], number uint32) bool {
	return r.Value != nil && r.Reason == "" && r.Value.Number == number
}

func matchesConnectivity(c *wire.Connectivity, f ExecutorFilter, now time.Time) bool {
	if len(f.AddressFamilies) == 0 && len(f.ReachableListeners) == 0 {
		return true
	}
	if c == nil || c.SchemaVersion != 1 {
		return false
	}
	for _, family := range f.AddressFamilies {
		r := c.IPv4
		if family == "ipv6" {
			r = c.IPv6
		}
		if !r.FreshReachable(now) {
			return false
		}
	}
	for _, listener := range f.ReachableListeners {
		r := c.TCPListener
		if listener == "udp" {
			r = c.UDPListener
		}
		if listener == "scion" {
			r = c.SCIONListener
		}
		if !r.FreshReachable(now) {
			return false
		}
	}
	return true
}
