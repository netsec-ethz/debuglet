// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "fmt"

// OutputConfig bounds retained output. Account and node limits include a fixed
// per-frame charge, so tiny writes consume capacity as well as large writes.
type OutputConfig struct {
	RunBytes     int64 `toml:"run_bytes"`
	RunFrames    int64 `toml:"run_frames"`
	AccountBytes int64 `toml:"account_bytes"`
	NodeBytes    int64 `toml:"node_bytes"`
}

func DefaultOutputConfig() OutputConfig {
	return OutputConfig{RunBytes: 8 << 20, RunFrames: 16384, AccountBytes: 128 << 20, NodeBytes: 1 << 30}
}

func (cfg OutputConfig) Validate() error {
	for _, field := range []struct {
		name  string
		value int64
	}{
		{"run_bytes", cfg.RunBytes}, {"run_frames", cfg.RunFrames},
		{"account_bytes", cfg.AccountBytes}, {"node_bytes", cfg.NodeBytes},
	} {
		if field.value <= 0 {
			return fmt.Errorf("output.%s must be positive", field.name)
		}
	}
	return nil
}
