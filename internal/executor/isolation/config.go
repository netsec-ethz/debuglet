// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package isolation owns the executor's local compiler and guest processes.
package isolation

import (
	"errors"
	"fmt"
	"math"
	"time"
)

var (
	ErrCompileWorker   = errors.New("compiler worker failed")
	ErrCompileBudget   = errors.New("compilation resource budget exceeded")
	ErrExecutionBudget = errors.New("execution resource budget exceeded")
	ErrAdmission       = errors.New("compiler capacity unavailable")
	ErrWorker          = errors.New("guest worker failed")
)

// Config is explicit for the shared Linux profile. Empty/trusted keeps the
// local in-process engine, which does not provide hard CPU/memory isolation.
// CPU values are microseconds per 100ms; memory includes the Go worker itself.
type Config struct {
	Profile                   string `toml:"profile"`
	CgroupRoot                string `toml:"cgroup_root"`
	NodeMemoryBytes           int64  `toml:"node_memory_bytes"`
	NodeCPUQuotaUS            int64  `toml:"node_cpu_quota_us"`
	NodePIDs                  int64  `toml:"node_pids"`
	ControlMemoryReserveBytes int64  `toml:"control_memory_reserve_bytes"`
	ControlCPUReserveUS       int64  `toml:"control_cpu_reserve_us"`
	CompileMemoryBytes        int64  `toml:"compile_memory_bytes"`
	CompileCPUQuotaUS         int64  `toml:"compile_cpu_quota_us"`
	CompileWallMS             int64  `toml:"compile_wall_ms"`
	CompileConcurrency        int    `toml:"compile_concurrency"`
	CompileQueue              int    `toml:"compile_queue"`
	RunMemoryBytes            int64  `toml:"run_memory_bytes"`
	RunCPUQuotaUS             int64  `toml:"run_cpu_quota_us"`
	RunWallMS                 int64  `toml:"run_wall_ms"`
	WorkerPIDs                int64  `toml:"worker_pids"`
	MemoryPages               uint32 `toml:"memory_pages"`
}

func (c Config) Shared() bool { return c.Profile == "shared" }
func (c Config) Validate() error {
	if c.Profile == "" || c.Profile == "trusted" {
		return nil
	}
	if !c.Shared() {
		return errors.New("isolation.profile must be trusted or shared")
	}
	if c.ControlMemoryReserveBytes <= 0 || c.ControlCPUReserveUS <= 0 || c.CgroupRoot == "" || c.NodeMemoryBytes <= 0 || c.NodeCPUQuotaUS <= 0 || c.NodePIDs <= 0 ||
		c.CompileMemoryBytes <= 0 || c.CompileCPUQuotaUS <= 0 || c.CompileWallMS <= 0 || c.CompileWallMS > int64(time.Hour/time.Millisecond) ||
		c.RunMemoryBytes <= 0 || c.RunCPUQuotaUS <= 0 || c.RunWallMS <= 0 || c.RunWallMS > int64(24*time.Hour/time.Millisecond) ||
		c.WorkerPIDs <= 0 || c.MemoryPages == 0 || c.MemoryPages > 65536 || c.CompileConcurrency <= 0 || c.CompileConcurrency > 1024 || c.CompileQueue < 0 || c.CompileQueue > 4096 {
		return errors.New("shared isolation requires a cgroup root and finite positive control reserves, memory, CPU, PID, page, phase time and concurrency limits")
	}
	if c.ControlMemoryReserveBytes > math.MaxInt64-c.NodeMemoryBytes || c.ControlCPUReserveUS > math.MaxInt64-c.NodeCPUQuotaUS {
		return errors.New("worker budgets plus control reserves overflow")
	}
	if max(c.CompileMemoryBytes, c.RunMemoryBytes) > c.NodeMemoryBytes || max(c.CompileCPUQuotaUS, c.RunCPUQuotaUS) > c.NodeCPUQuotaUS || c.WorkerPIDs > c.NodePIDs {
		return fmt.Errorf("worker resource budgets exceed node budgets")
	}
	if int64(c.MemoryPages)*65536 > c.RunMemoryBytes {
		return errors.New("WASM page budget exceeds worker memory budget")
	}
	return nil
}
