// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"net/netip"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// ConnectivityConfig contains only operator-selected controlled peers. These
// values cannot be supplied by a measurement or by the dispatcher at runtime.
type ConnectivityConfig struct {
	IPv4Reflector   string `toml:"ipv4_reflector"`
	IPv6Reflector   string `toml:"ipv6_reflector"`
	Listeners       bool   `toml:"listeners"`
	SCIONPathTarget string `toml:"scion_path_target"`
}

func (c ConnectivityConfig) Validate(plaintext bool) error {
	for _, target := range []struct {
		name, value string
		v4          bool
	}{
		{"ipv4_reflector", c.IPv4Reflector, true}, {"ipv6_reflector", c.IPv6Reflector, false},
	} {
		if target.value == "" {
			continue
		}
		endpoint, err := netip.ParseAddrPort(target.value)
		if err != nil || endpoint.Port() == 0 || endpoint.Addr().Is4() != target.v4 || endpoint.Addr().Is4In6() || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Addr().Zone() != "" {
			return fmt.Errorf("connectivity.%s must be a literal address and nonzero port of its stated family", target.name)
		}
		if plaintext && !endpoint.Addr().IsLoopback() {
			return fmt.Errorf("connectivity.%s requires TLS outside loopback", target.name)
		}
	}
	if c.SCIONPathTarget != "" {
		if _, ok := wire.CanonicalISDAS(c.SCIONPathTarget); !ok {
			return fmt.Errorf("connectivity.scion_path_target must be a concrete ISD-AS")
		}
	}
	return nil
}
