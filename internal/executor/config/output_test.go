// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestOutputLimits(t *testing.T) {
	c := OutputConfig{}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Limits().RunBytes != 8<<20 || c.Limits().NodeBytes != 64<<20 {
		t.Fatal("output defaults")
	}
	if r, b := c.Rate(); r != 1<<20 || b != 64<<10 {
		t.Fatal("rate defaults")
	}
	for _, c := range []OutputConfig{{ControlReserveBytes: -1}, {ControlReserveBytes: (1 << 40) + 1}, {RunBytes: -1}, {RunFrames: -1}, {SpoolBytes: 1}, {RetainedRuns: -1}, {RateBytesPerSecond: -1}, {BurstBytes: 1}, {BurstBytes: 2 << 20}} {
		if c.Validate() == nil {
			t.Fatalf("invalid output limits accepted: %+v", c)
		}
	}
}
