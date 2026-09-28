// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ExecutorFilter requires every specified observation. Unknown capabilities do
// not match requested filters. Capacity is advertised total bandwidth, not a
// reservation or a promise that a particular run can be admitted.
type ExecutorFilter struct {
	Protocols       []string
	EnforcementMode string
	MinCapacityBPS  *int64
}

func (f ExecutorFilter) Empty() bool {
	return len(f.Protocols) == 0 && f.EnforcementMode == "" && f.MinCapacityBPS == nil
}

func (f ExecutorFilter) Validate() error {
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
		if !node.Ready || strings.TrimSpace(node.ID) == "" {
			continue
		}
		if filter.Empty() {
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
		return Node{}, errors.New("no ready executor matches; check dbl nodes and the requested capability filters")
	}
	return *selected, nil
}
