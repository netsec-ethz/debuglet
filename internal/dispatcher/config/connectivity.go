// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
)

func validateConnectivityTarget(id string, c ExecutorDisplay) error {
	if c.ConnectivityHost == "" && c.ConnectivityPorts == "" {
		return nil
	}
	ip, err := netip.ParseAddr(c.ConnectivityHost)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.Zone() != "" {
		return fmt.Errorf("executors.%q.connectivity_host must be a literal unicast address", id)
	}
	ports, err := socket.ParsePortRanges(c.ConnectivityPorts)
	if err != nil || len(ports) == 0 || len(ports) > 256 {
		return fmt.Errorf("executors.%q.connectivity_ports must contain 1 to 256 controlled listener ports", id)
	}
	return nil
}

// ConnectivityTarget returns an endpoint only when its port belongs to the
// operator's bounded pool. The advertised host never supplies a dial target.
func (c ExecutorDisplay) ConnectivityTarget(port uint32) (netip.AddrPort, bool) {
	if port == 0 || port > 65535 {
		return netip.AddrPort{}, false
	}
	ip, err := netip.ParseAddr(c.ConnectivityHost)
	if err != nil {
		return netip.AddrPort{}, false
	}
	ports, err := socket.ParsePortRanges(c.ConnectivityPorts)
	if err != nil || !slices.Contains(ports, int(port)) {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}
