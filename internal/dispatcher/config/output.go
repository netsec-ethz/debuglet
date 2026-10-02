// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/storageheadroom"
)

// OutputConfig bounds retained output. Account and node limits include a fixed
// per-frame charge, so tiny writes consume capacity as well as large writes.
// Payload deletion releases the exact charge once; reference metadata remains.
// Zero explicitly disables an aggregate cap only in the local TEST profile.
type OutputConfig struct {
	ControlReserveBytes int64 `toml:"control_reserve_bytes"`
	RunBytes            int64 `toml:"run_bytes"`
	RunFrames           int64 `toml:"run_frames"`
	AccountBytes        int64 `toml:"account_bytes"`
	NodeBytes           int64 `toml:"node_bytes"`
}

func DefaultOutputConfig() OutputConfig {
	return OutputConfig{ControlReserveBytes: storageheadroom.DefaultReserveBytes, RunBytes: 8 << 20, RunFrames: 16384, AccountBytes: 64 << 20, NodeBytes: 512 << 20}
}

func (cfg OutputConfig) Validate() error {
	if cfg.ControlReserveBytes <= 0 || cfg.ControlReserveBytes > 1<<40 {
		return fmt.Errorf("output.control_reserve_bytes must be positive and at most 1 TiB")
	}
	if cfg.RunBytes <= 0 {
		return fmt.Errorf("output.run_bytes must be positive")
	}
	if cfg.RunFrames <= 0 {
		return fmt.Errorf("output.run_frames must be positive")
	}
	if cfg.AccountBytes < 0 {
		return fmt.Errorf("output.account_bytes must be zero (no cap) or positive")
	}
	if cfg.NodeBytes < 0 {
		return fmt.Errorf("output.node_bytes must be zero (no cap) or positive")
	}
	return nil
}
