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

func TestAddressPublicationConfiguration(t *testing.T) {
	cfg, _, err := DecodeConfig([]byte(baseSections))
	if err != nil || cfg.Metadata.AddressOptOut || !cfg.Connectivity.ObserveAddresses {
		t.Fatalf("defaults are not public with address observation: %+v %v", cfg, err)
	}
	cfg, _, err = DecodeConfig([]byte(baseSections + "[metadata]\naddress_opt_out=true\n[connectivity]\nobserve_addresses=false\n"))
	if err != nil || !cfg.Metadata.AddressOptOut || cfg.Metadata.LocationOptOut || cfg.Connectivity.ObserveAddresses {
		t.Fatalf("explicit settings not kept: %+v %v", cfg, err)
	}
}
