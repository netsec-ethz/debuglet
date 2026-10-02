// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
	"testing"
)

func TestSharedIsolationRejectsUnsupportedTransport(t *testing.T) {
	cfg := ExecutorConfig{Isolation: isolation.Config{Profile: "shared", CgroupRoot: "/delegated", NodeMemoryBytes: 256 << 20, NodeCPUQuotaUS: 100000, NodePIDs: 64,
		ControlMemoryReserveBytes: 128 << 20, ControlCPUReserveUS: 25000,
		CompileMemoryBytes: 256 << 20, CompileCPUQuotaUS: 100000, CompileWallMS: 10000, CompileConcurrency: 1,
		RunMemoryBytes: 256 << 20, RunCPUQuotaUS: 100000, RunWallMS: 10000, WorkerPIDs: 64, MemoryPages: 1024}}
	if err := cfg.ValidateIsolation(); err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg.Network.Policy.SCION = &enabled
	if err := cfg.ValidateIsolation(); err == nil {
		t.Fatal("shared SCION accepted")
	}
	cfg.Isolation.Profile = "trusted"
	if err := cfg.ValidateIsolation(); err != nil {
		t.Fatal("trusted transport configuration:", err)
	}
}
