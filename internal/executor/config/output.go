// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// OutputConfig bounds emitted data and its retained spool. Zero selects the
// documented default; acknowledged metadata still counts toward retained_runs.
type OutputConfig struct {
	RunBytes           int64 `toml:"run_bytes"`
	RunFrames          int64 `toml:"run_frames"`
	SpoolBytes         int64 `toml:"spool_bytes"`
	RetainedRuns       int64 `toml:"retained_runs"`
	RateBytesPerSecond int64 `toml:"rate_bytes_per_second"`
	BurstBytes         int   `toml:"burst_bytes"`
}

func (c OutputConfig) Limits() outputstore.Limits {
	l := outputstore.DefaultLimits()
	if c.RunBytes != 0 {
		l.RunBytes = c.RunBytes
	}
	if c.RunFrames != 0 {
		l.RunFrames = c.RunFrames
	}
	if c.SpoolBytes != 0 {
		l.NodeBytes = c.SpoolBytes
	}
	if c.RetainedRuns != 0 {
		l.Runs = c.RetainedRuns
	}
	return l
}

func (c OutputConfig) Rate() (int64, int) {
	r, b := c.RateBytesPerSecond, c.BurstBytes
	if r == 0 {
		r = 1 << 20
	}
	if b == 0 {
		b = 64 << 10
	}
	return r, b
}

func (c OutputConfig) Validate() error {
	l := c.Limits()
	if l.RunBytes <= 0 || l.RunFrames <= 0 || l.NodeBytes < pb.OutputRunCharge || l.Runs <= 0 {
		return fmt.Errorf("output storage limits must be positive and spool_bytes at least %d", pb.OutputRunCharge)
	}
	r, b := c.Rate()
	if r <= 0 || r > 1<<30 || b < pb.MaxOutputFrameBytes || b > 1<<20 {
		return fmt.Errorf("output rate_bytes_per_second must be between 1 and 1073741824; burst_bytes between %d and 1048576", pb.MaxOutputFrameBytes)
	}
	return nil
}
