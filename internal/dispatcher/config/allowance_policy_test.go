// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"math"
	"testing"

	"github.com/google/uuid"
)

func TestAllowancePolicyConfig(t *testing.T) {
	base := AllowanceConfig{Enabled: true, PolicyIssuer: uuid.NewString(), DailyBase: 100, DailyPerNode: 10, DailyNodeCap: 3, PublicTrial: 10}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []AllowanceConfig{base, base, base, base, base, base}
	cases[0].Enabled = false
	cases[1].PolicyIssuer = ""
	cases[2].DailyBase = -1
	cases[3].DailyNodeCap = 101
	cases[4].DailyBase = math.MaxInt64
	cases[5].PublicTrial = -1
	for i, cfg := range cases {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("invalid config %d accepted", i)
		}
	}
	if cfg := DefaultAllowanceConfig(); cfg.Automatic() || cfg.Validate() != nil {
		t.Fatal("automatic policy must be opt-in")
	}
}
