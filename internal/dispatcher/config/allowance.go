// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "fmt"

// AllowanceConfig governs usage allowances: fixed grants of TEST units an
// operator issues to an account, which cap what the account may reserve with
// TEST payment intents. Allowances are usage credits, not money; they cannot be
// transferred and nothing grants them automatically. Disabled, the default,
// TEST intents are not capped.
type AllowanceConfig struct {
	Enabled bool `toml:"enabled"`
	// DefaultGrant is the amount, in TEST units, of a grant whose request names
	// none. Omitted or 0 means DefaultAllowanceGrant.
	DefaultGrant int64 `toml:"default_grant"`
}

// DefaultAllowanceGrant is the documented default of allowance.default_grant:
// ten runs of the default 100,000 bit/s for 30 seconds at a price of 1.
const DefaultAllowanceGrant int64 = 30_000_000

func DefaultAllowanceConfig() AllowanceConfig {
	return AllowanceConfig{DefaultGrant: DefaultAllowanceGrant}
}

// Grant is the configured default grant, with 0 resolved to the default, so a
// configuration built in code without it keeps the documented default.
func (cfg AllowanceConfig) Grant() int64 {
	if cfg.DefaultGrant == 0 {
		return DefaultAllowanceGrant
	}
	return cfg.DefaultGrant
}

func (cfg AllowanceConfig) Validate() error {
	if cfg.DefaultGrant < 0 {
		return fmt.Errorf("allowance.default_grant must be 0 (the default of %d TEST units) or positive, got %d",
			DefaultAllowanceGrant, cfg.DefaultGrant)
	}
	return nil
}
