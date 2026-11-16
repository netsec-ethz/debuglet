// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"math"

	"github.com/google/uuid"
)

// AllowanceConfig governs usage allowances: fixed grants of TEST units an
// operator issues to an account, which cap what the account may reserve with
// TEST payment intents. Allowances are usage credits, not money; they cannot be
// transferred. Automatic refills require an explicit policy issuer. When
// disabled (the default), TEST intents are not capped.
type AllowanceConfig struct {
	Enabled bool `toml:"enabled"`
	// DefaultGrant is the amount, in TEST units, of a grant whose request names
	// none. Omitted or 0 means DefaultAllowanceGrant.
	DefaultGrant int64 `toml:"default_grant"`
	// Automatic policy is opt-in. PolicyIssuer must name an operator account.
	PolicyIssuer string `toml:"policy_issuer"`
	DailyBase    int64  `toml:"daily_base"`
	DailyPerNode int64  `toml:"daily_per_node"`
	DailyNodeCap int    `toml:"daily_node_cap"`
	PublicTrial  int64  `toml:"public_trial"`
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
	if cfg.DailyBase < 0 || cfg.DailyPerNode < 0 || cfg.PublicTrial < 0 || cfg.DailyNodeCap < 0 || cfg.DailyNodeCap > 100 {
		return fmt.Errorf("allowance policy amounts must be non-negative and daily_node_cap must be between 0 and 100")
	}
	if cfg.DailyNodeCap > 0 && cfg.DailyPerNode > (math.MaxInt64-cfg.DailyBase)/int64(cfg.DailyNodeCap) {
		return fmt.Errorf("allowance daily ceiling overflows")
	}
	if cfg.PolicyIssuer != "" || cfg.DailyBase != 0 || cfg.DailyPerNode != 0 || cfg.PublicTrial != 0 {
		id, err := uuid.Parse(cfg.PolicyIssuer)
		if !cfg.Enabled || err != nil || id == uuid.Nil {
			return fmt.Errorf("automatic allowances require enabled=true and a valid policy_issuer account UUID")
		}
	}
	return nil
}

func (cfg AllowanceConfig) Automatic() bool { return cfg.Enabled && cfg.PolicyIssuer != "" }
