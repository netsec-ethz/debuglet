// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package isolation

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestControlCapacityRequiresFiniteDelegationAndAncestorRoom(t *testing.T) {
	for _, tc := range []struct {
		name, memory, cpu, ancestorMemory, ancestorCPU string
		wantError                                      bool
	}{
		{"exact_capacity", "671088640", "125000 100000", "max", "max 100000", false},
		{"different_period", "671088640", "375000 300000", "max", "max 100000", false},
		{"wide_product", "671088640", "9223372036854775807 9223372036854775807", "max", "max 100000", true},
		{"large_quota", "671088640", "9223372036854775807 100000", "max", "max 100000", false},
		{"no_rounding_room", "671088640", "125001 100001", "max", "max 100000", true},
		{"unbounded_memory", "max", "125000 100000", "671088640", "125000 100000", true},
		{"unbounded_cpu", "671088640", "max 100000", "671088640", "125000 100000", true},
		{"memory_reserve_missing", "536870912", "125000 100000", "max", "max 100000", true},
		{"cpu_reserve_missing", "671088640", "100000 100000", "max", "max 100000", true},
		{"tighter_memory_ancestor", "671088640", "125000 100000", "600000000", "max 100000", true},
		{"tighter_cpu_ancestor", "671088640", "125000 100000", "max", "240000 200000", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			boundary := t.TempDir()
			parent := filepath.Join(boundary, "service")
			root := filepath.Join(parent, "delegation")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			for path, limits := range map[string][2]string{root: {tc.memory, tc.cpu}, parent: {tc.ancestorMemory, tc.ancestorCPU}} {
				for i, name := range []string{"memory.max", "cpu.max"} {
					if err := os.WriteFile(filepath.Join(path, name), []byte(limits[i]), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			cfg := Config{CgroupRoot: root, NodeMemoryBytes: 512 << 20, ControlMemoryReserveBytes: 128 << 20, NodeCPUQuotaUS: 100000, ControlCPUReserveUS: 25000}
			if err := checkControlCapacity(cfg, boundary); (err != nil) != tc.wantError {
				t.Fatalf("capacity error=%v; want error=%t", err, tc.wantError)
			}
		})
	}
}

func TestSharedControlReserveValidation(t *testing.T) {
	valid := Config{Profile: "shared", CgroupRoot: "/delegated", NodeMemoryBytes: 256 << 20, NodeCPUQuotaUS: 100000, NodePIDs: 64,
		ControlMemoryReserveBytes: 128 << 20, ControlCPUReserveUS: 25000,
		CompileMemoryBytes: 256 << 20, CompileCPUQuotaUS: 100000, CompileWallMS: 10000, CompileConcurrency: 1,
		RunMemoryBytes: 256 << 20, RunCPUQuotaUS: 100000, RunWallMS: 10000, WorkerPIDs: 64, MemoryPages: 1024}
	for _, change := range []func(*Config){
		func(c *Config) { c.ControlMemoryReserveBytes = 0 },
		func(c *Config) { c.ControlCPUReserveUS = 0 },
		func(c *Config) { c.ControlMemoryReserveBytes = -1 },
		func(c *Config) { c.ControlCPUReserveUS = -1 },
		func(c *Config) { c.ControlMemoryReserveBytes = math.MaxInt64 },
		func(c *Config) { c.ControlCPUReserveUS = math.MaxInt64 },
	} {
		cfg := valid
		change(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatal("invalid control reserve accepted")
		}
	}
}
