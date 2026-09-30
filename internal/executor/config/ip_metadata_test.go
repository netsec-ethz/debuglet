// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestLocationOptOutConfiguration(t *testing.T) {
	for _, optOut := range []bool{false, true} {
		text := "false"
		if optOut {
			text = "true"
		}
		cfg, _, err := DecodeConfig([]byte(baseSections + "[metadata]\nlocation_opt_out=" + text + "\n"))
		if err != nil || cfg.Metadata.LocationOptOut != optOut {
			t.Fatalf("optout %t: %+v %v", optOut, cfg, err)
		}
	}
}
