// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "fmt"

// OutputConfig bounds retained output. Account and node limits include a fixed
// per-frame charge, so tiny writes consume capacity as well as large writes.
// The dispatcher does not yet delete retained output, so account and node
// charges only grow; those two caps are therefore opt-in (zero disables them)
// until a retention policy can release capacity.
type OutputConfig struct {
	RunBytes     int64 `toml:"run_bytes"`
	RunFrames    int64 `toml:"run_frames"`
	AccountBytes int64 `toml:"account_bytes"`
	NodeBytes    int64 `toml:"node_bytes"`
}

func DefaultOutputConfig() OutputConfig {
	return OutputConfig{RunBytes: 8 << 20, RunFrames: 16384, AccountBytes: 0, NodeBytes: 0}
}

func (cfg OutputConfig) Validate() error {
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
