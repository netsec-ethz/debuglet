// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
	"github.com/netsec-ethz/debuglet/internal/fsutil"
	"github.com/pelletier/go-toml/v2"
)

// The preset bounds four workers without changing the enrolled executor's
// admission setting. Its service limits also leave room for the control process.
func sharedPreset(p Profile) isolation.Config {
	return isolation.Config{
		Profile: "shared", CgroupRoot: filepath.Join("/sys/fs/cgroup/system.slice", p.Unit),
		NodeMemoryBytes: 1 << 30, NodeCPUQuotaUS: 200000, NodePIDs: 256,
		ControlMemoryReserveBytes: 256 << 20, ControlCPUReserveUS: 25000,
		CompileMemoryBytes: 256 << 20, CompileCPUQuotaUS: 50000,
		CompileWallMS: 60000, CompileConcurrency: 1, CompileQueue: 3,
		RunMemoryBytes: 256 << 20, RunCPUQuotaUS: 50000,
		RunWallMS: 86400000, WorkerPIDs: 64, MemoryPages: 1024,
	}
}

func prepareSharedConfig(p Profile) (bool, error) {
	data, err := os.ReadFile(p.ConfigPath)
	if err != nil {
		return false, err
	}
	cfg, document, err := executorconfig.DecodeConfig(data)
	if err != nil {
		return false, err
	}
	if cfg.Resources.MaxDebuglets > 4 {
		return false, errors.New("the managed shared preset supports resources.max_debuglets up to 4; review that setting before installation")
	}
	preset := sharedPreset(p)
	if document.Set("isolation") {
		if cfg.Isolation == preset {
			return false, nil // Includes recovery after configuration was published.
		}
		return false, errors.New("--isolation shared does not replace existing isolation configuration; retain the custom host setup described in docs/operations/guest-isolation.md")
	}
	if p.ExecutorID != "" {
		return false, errors.New("managed shared isolation configuration was removed; restore it before reinstalling")
	}
	section, err := toml.Marshal(struct {
		Isolation isolation.Config `toml:"isolation"`
	}{preset})
	if err != nil {
		return false, err
	}
	data = append(append(data, '\n'), section...)
	if _, _, err := executorconfig.DecodeConfig(data); err != nil {
		return false, fmt.Errorf("shared isolation configuration: %w", err)
	}
	return true, fsutil.WriteFile(p.ConfigPath, data, 0600)
}

// Check prerequisites before modifying a real installation. The daemon checks
// the actual delegation, ancestor capacity and kernel operations at startup.
func checkSharedHost(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return errors.New("managed shared isolation requires Linux 5.14+, cgroup v2 and systemd 254+")
	}
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return err
	}
	var major, minor int
	if _, err := fmt.Sscanf(string(kernel), "%d.%d", &major, &minor); err != nil || major < 5 || major == 5 && minor < 14 {
		return errors.New("managed shared isolation requires Linux 5.14 or newer")
	}
	version, err := exec.CommandContext(ctx, "systemctl", "--version").Output()
	if err != nil {
		return fmt.Errorf("managed shared isolation requires systemd 254+: %w", err)
	}
	var systemd int
	if _, err := fmt.Sscanf(string(version), "systemd %d", &systemd); err != nil || systemd < 254 {
		return errors.New("managed shared isolation requires systemd 254+ for DelegateSubgroup")
	}
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return fmt.Errorf("managed shared isolation requires cgroup v2 mounted at /sys/fs/cgroup: %w", err)
	}
	available := " " + strings.Join(strings.Fields(string(controllers)), " ") + " "
	for _, name := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(available, " "+name+" ") {
			return fmt.Errorf("managed shared isolation requires the cgroup v2 %s controller", name)
		}
	}
	return nil
}
