// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// EgressLimits are reserved for a complete fixed window. Payload bytes exclude
// IP/TCP/TLS headers and retransmissions. Attempts include failed connects;
// targets count each run's distinct pinned addresses conservatively.
type EgressLimits struct {
	BitsPerSecond     int64 `toml:"bits_per_second"`
	BurstBytes        int64 `toml:"burst_bytes"`
	Bytes             int64 `toml:"bytes"`
	AttemptsPerSecond int64 `toml:"attempts_per_second"`
	AttemptBurst      int64 `toml:"attempt_burst"`
	Attempts          int64 `toml:"attempts"`
	Targets           int64 `toml:"targets"`
}

type EgressGroup struct {
	Name     string       `toml:"name"`
	Prefixes []string     `toml:"prefixes"`
	Names    []string     `toml:"names"`
	Limits   EgressLimits `toml:"limits"`
}

type EgressConfig struct {
	Enabled       bool          `toml:"enabled"`
	WindowSeconds int64         `toml:"window_seconds"`
	Run           EgressLimits  `toml:"run"`
	Account       EgressLimits  `toml:"account"`
	Node          EgressLimits  `toml:"node"`
	Groups        []EgressGroup `toml:"groups"`
}

func (l EgressLimits) Values() [7]int64 {
	return [7]int64{l.BitsPerSecond, l.BurstBytes, l.Bytes, l.AttemptsPerSecond, l.AttemptBurst, l.Attempts, l.Targets}
}

func (c EgressConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.WindowSeconds < 1 || c.WindowSeconds > 86400 || len(c.Groups) > 64 {
		return fmt.Errorf("egress requires window_seconds between 1 and 86400 and at most 64 groups")
	}
	limits := []EgressLimits{c.Run, c.Account, c.Node}
	names := make(map[string]bool)
	for _, group := range c.Groups {
		if group.Name == "" || len(group.Name) > 64 || strings.ContainsAny(group.Name, ":\x00\r\n\t ") || names[group.Name] || len(group.Prefixes)+len(group.Names) == 0 || len(group.Prefixes)+len(group.Names) > 256 {
			return fmt.Errorf("egress groups require unique names and bounded destination selectors")
		}
		names[group.Name] = true
		for _, prefix := range group.Prefixes {
			p, err := netip.ParsePrefix(prefix)
			if err != nil {
				return fmt.Errorf("egress group %s: %w", group.Name, err)
			}
			if p.Addr().Is4In6() && p.Bits() < 96 {
				return fmt.Errorf("egress group %s: IPv4-mapped prefix must include at least 96 bits", group.Name)
			}
		}
		for _, name := range group.Names {
			if name == "" || len(name) > 253 || strings.ContainsAny(name, " /:,\x00\r\n\t") {
				return fmt.Errorf("egress group %s: invalid DNS name", group.Name)
			}
		}
		limits = append(limits, group.Limits)
	}
	for _, limit := range limits {
		for _, value := range limit.Values() {
			if value < 1 || value > 1<<50 {
				return fmt.Errorf("egress limits must be positive and no greater than 1125899906842624")
			}
		}
	}
	if c.Run.BitsPerSecond > 1<<40 || c.Run.BurstBytes > 16<<20 || c.Run.AttemptsPerSecond > 1_000_000 || c.Run.AttemptBurst > 1_000_000 || c.Run.Attempts > 1_000_000 || c.Run.Targets > 256 {
		return fmt.Errorf("egress per-run limits exceed the supported grant bounds")
	}
	return nil
}
