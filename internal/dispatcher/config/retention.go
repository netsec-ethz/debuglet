// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"time"
)

// RetentionConfig governs completed measurement payloads. Zero preserves them
// until their owner deletes them. This does not expire identities, accounting,
// verification references, active runs or uncertain remote ownership.
type RetentionConfig struct {
	PayloadMaxAgeSeconds int64 `toml:"payload_max_age_seconds"`
}

func (cfg RetentionConfig) Validate() error {
	if cfg.PayloadMaxAgeSeconds < 0 || cfg.PayloadMaxAgeSeconds > int64((1<<63-1)/time.Second) {
		return fmt.Errorf("retention.payload_max_age_seconds must be zero (no automatic expiry) or a positive representable duration")
	}
	return nil
}

func (cfg RetentionConfig) PayloadMaxAge() time.Duration {
	return time.Duration(cfg.PayloadMaxAgeSeconds) * time.Second
}
