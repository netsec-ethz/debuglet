// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"strconv"
	"strings"
	"testing"
)

func TestStudioSocketConfiguration(t *testing.T) {
	for _, path := range []string{"", "/run/debuglet-studio/worker.sock"} {
		cfg, _, err := DecodeConfig([]byte(commonSections + "\n[studio]\nsocket_path = " + strconv.Quote(path)))
		if err != nil || cfg.Studio.SocketPath != path {
			t.Fatalf("socket %q: config=%v error=%v", path, cfg, err)
		}
	}
	cfg, _, err := DecodeConfig([]byte(commonSections))
	if err != nil || cfg.Studio.SocketPath != "" {
		t.Fatalf("omitted studio must stay disabled: %v, %v", cfg, err)
	}
	for _, path := range []string{"relative.sock", " ", "/run/../tmp/worker.sock", "/run//worker.sock", "/" + strings.Repeat("x", 107), "/run/worker\x00.sock"} {
		if (StudioConfig{SocketPath: path}).Validate() == nil {
			t.Errorf("accepted invalid socket path %q", path)
		}
	}
}
