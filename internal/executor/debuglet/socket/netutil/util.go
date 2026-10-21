// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netutil

import (
	"fmt"
	"net/netip"

	"github.com/netsec-ethz/debuglet/internal/netaddr"
)

type IPv6 struct {
	IP netip.Addr
}

func (ip IPv6) String() string {
	return ip.IP.String()
}

// ToIPv6 keys an address in the 16-byte form the packet counters use: an IPv4
// address becomes its IPv4-mapped IPv6 form, and an IPv6 address, including
// its zone, is kept as it is.
func ToIPv6(addr netip.Addr) IPv6 {
	if addr.Is4() {
		return IPv6{IP: netip.AddrFrom16(addr.As16())}
	}
	return IPv6{IP: addr}
}

// SplitOptionalPort splits a host and optional port without changing their spelling.
func SplitOptionalPort(address string) (host, port string, hasPort bool, err error) {
	return netaddr.SplitOptionalPort(address)
}

// HostFromAddr returns the host of "host:port", or the address itself when it
// has no port.
func HostFromAddr(addr string) (string, error) {
	host, _, _, err := SplitOptionalPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address format: %w", err)
	}
	return host, nil
}
