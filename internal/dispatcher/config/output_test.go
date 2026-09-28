// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestOutputConfigDefaultsAndLimits(t *testing.T) {
	cfg, _, err := DecodeConfig([]byte(baseSections))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output != DefaultOutputConfig() {
		t.Fatalf("defaults: %+v", cfg.Output)
	}
	for _, key := range []string{"run_bytes", "run_frames", "account_bytes", "node_bytes"} {
		if _, _, err := DecodeConfig([]byte(baseSections + "\n[output]\n" + key + " = 0\n")); err == nil {
			t.Fatalf("accepted zero %s", key)
		}
	}
	cfg, _, err = DecodeConfig([]byte(baseSections + "\n[output]\nrun_bytes = 1024\nnode_bytes = 4096\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output.RunBytes != 1024 || cfg.Output.NodeBytes != 4096 || cfg.Output.RunFrames != DefaultOutputConfig().RunFrames {
		t.Fatalf("partial configuration: %+v", cfg.Output)
	}
}
