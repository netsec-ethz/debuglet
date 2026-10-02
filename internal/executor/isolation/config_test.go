// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package isolation

import "testing"

func TestSharedProfileRequiresExplicitBudgets(t *testing.T) {
	if err := (Config{}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Config{Profile: "shared"}).Validate(); err == nil {
		t.Fatal("empty shared budgets accepted")
	}
	valid := Config{Profile: "shared", CgroupRoot: t.TempDir(), NodeMemoryBytes: 256 << 20, NodeCPUQuotaUS: 100000, NodePIDs: 64,
		ControlMemoryReserveBytes: 128 << 20, ControlCPUReserveUS: 25000,
		CompileMemoryBytes: 256 << 20, CompileCPUQuotaUS: 100000, CompileWallMS: 10000, CompileConcurrency: 1,
		RunMemoryBytes: 256 << 20, RunCPUQuotaUS: 100000, RunWallMS: 10000, WorkerPIDs: 64, MemoryPages: 1024}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(valid); err == nil {
		t.Fatal("ordinary directory accepted")
	}
	if err := (Config{Profile: "automatic"}).Validate(); err == nil {
		t.Fatal("unknown fallback accepted")
	}
}
