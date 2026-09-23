// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netutil

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type IPv6 struct {
	IP netip.Addr
}

func (ip IPv6) String() string {
	return ip.IP.String()
}

func ToIPv6(addr netip.Addr) IPv6 {
	if addr.Is4() {
		ip4 := addr.As4()
		return IPv6{IP: netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, ip4[0], ip4[1], ip4[2], ip4[3]})}
	}
	return IPv6{IP: addr}
}

func HostFromAddr(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" {
			host = addr
		} else {
			return "", fmt.Errorf("invalid address format: %w", err)
		}
	}
	return host, nil
}
