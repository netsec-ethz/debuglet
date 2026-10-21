// Copyright 2025 ETH Zurich
// Copyright 2026 ETH Zurich
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

// Package netaddr parses configured ports and canonical destination addresses
// shared by dispatchers, executors and traffic accounting. It holds no policy
// or runtime state.
package netaddr

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Normalize is the one spelling of an address the policy works with: no IPv4
// mapping, no zone. Two guests writing the same destination differently reach
// the same decision, and the same accounting key.
func Normalize(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// DestinationKey is the one spelling of a destination the set compares: the
// normalized address, or the lower-case name without a trailing dot. A SCION
// address or a port is reduced to its host, as for a declared destination.
func DestinationKey(destination string) string {
	host := DeclaredHost(destination)
	if addr, err := netip.ParseAddr(host); err == nil {
		return Normalize(addr).String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// DeclaredHost reads the host out of one declared destination. A declared
// destination is normally a name or an address; a SCION address carries its
// host after the last comma, and a port is not part of a declaration.
func DeclaredHost(declared string) string {
	declared = strings.TrimSpace(declared)
	if index := strings.LastIndex(declared, ","); index >= 0 {
		declared = declared[index+1:]
	}
	if declared == "" {
		return ""
	}
	if _, err := netip.ParseAddr(declared); err == nil {
		return declared
	}
	if host, _, err := SplitHostPort(declared); err == nil && host != "" {
		return host
	}
	return declared
}

// SplitHostPort accepts both "host:port" and a bare host. A bracketed IPv6
// literal keeps its brackets off the returned host.
func SplitHostPort(address string) (string, int, error) {
	host, port, hasPort, err := SplitOptionalPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("invalid address %q", address)
	}
	if !hasPort {
		return strings.Trim(host, "[]"), 0, nil
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return "", 0, fmt.Errorf("invalid port %q in address %q", port, address)
	}
	return host, number, nil
}

// SplitOptionalPort splits "host:port" like net.SplitHostPort, and also
// accepts an address without a port, for which it returns the address itself
// as host and hasPort false. A bare bracketed IPv6 literal keeps its brackets.
// Any other malformed address returns net.SplitHostPort's error.
func SplitOptionalPort(address string) (host, port string, hasPort bool, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" {
			return address, "", false, nil
		}
		return "", "", false, err
	}
	return host, port, true, nil
}
