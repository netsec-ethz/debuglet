// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"time"
)

// AttributionConfig bounds the attribution history the dispatcher keeps for
// probe verification: the TESLA chains executors announced, their disclosed
// keys and the source addresses and intervals of runs.
type AttributionConfig struct {
	// RetentionDays is how long the history is kept. Older records are pruned
	// periodically, and GET /attribution/candidates reports the resulting
	// retained_from. Omitted means DefaultAttributionRetentionDays.
	RetentionDays int `toml:"retention_days"`
}

// Documented default and bound of attribution.retention_days.
const (
	DefaultAttributionRetentionDays = 90
	MaxAttributionRetentionDays     = 3650
)

func DefaultAttributionConfig() AttributionConfig {
	return AttributionConfig{RetentionDays: DefaultAttributionRetentionDays}
}

// Retention is the configured retention as a duration.
func (cfg AttributionConfig) Retention() time.Duration {
	return time.Duration(cfg.RetentionDays) * 24 * time.Hour
}

func (cfg AttributionConfig) Validate() error {
	if cfg.RetentionDays < 1 || cfg.RetentionDays > MaxAttributionRetentionDays {
		return fmt.Errorf("attribution.retention_days must be between 1 and %d, got %d", MaxAttributionRetentionDays, cfg.RetentionDays)
	}
	return nil
}
