// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
)

func TestJoinCapacityAndCounterSelection(t *testing.T) {
	for _, tc := range []struct{ state, counter string }{
		{"/home/fixture/node", "fallback"},
		{"/var/lib/debuglet/executors/worker", "fallback"},
	} {
		counter := tc.counter
		config, _, err := executorconfig.DecodeConfig([]byte(executorJoinConfig(joinExecutorID, tc.state, executorJoinResponse{GRPCAddress: "127.0.0.1:9001", YamuxAddress: "127.0.0.1:9000"}, nil, 2_000_000)))
		if err != nil {
			t.Fatal(err)
		}
		if config.Resources.Capacity != 2_000_000 || config.Network.PacketCounter != counter {
			t.Fatalf("capacity/counter: %+v %+v", config.Resources, config.Network)
		}
	}
	fixture := newJoinFixture(t, nil)
	state := filepath.Join(t.TempDir(), "executor")
	code, out, errout := runCLI(context.Background(), append(fixture.args(state), "--capacity", "3000000")...)
	assertCode(t, code, exitOK, out, errout)
	data, err := os.ReadFile(filepath.Join(state, "service.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "capacity = 3000000") || !strings.Contains(out, "TCP/TLS remain untagged") {
		t.Fatalf("join capacity or disclosure missing: %s\n%s", data, out)
	}
	for _, value := range []string{"0", "-1"} {
		args := append(fixture.args(filepath.Join(t.TempDir(), "rejected")), "--capacity", value)
		code, _, _ := runCLI(context.Background(), args...)
		if code != exitUsage {
			t.Fatalf("capacity %s accepted: %d", value, code)
		}
	}
}
