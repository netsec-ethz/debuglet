// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package isolation

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// checkControlCapacity checks configured capacity, not a racy free-memory
// observation. The exclusive delegation and its visible ancestors must leave
// the declared reserves outside the aggregate worker limits. Other workloads
// and the parent's own allocations can still consume that capacity.
func checkControlCapacity(c Config, boundary string) error {
	root := filepath.Clean(c.CgroupRoot)
	relative, err := filepath.Rel(boundary, root)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return errors.New("shared isolation requires a finite delegation below /sys/fs/cgroup")
	}
	memory := c.NodeMemoryBytes + c.ControlMemoryReserveBytes
	cpu := c.NodeCPUQuotaUS + c.ControlCPUReserveUS
	for path := root; path != boundary; path = filepath.Dir(path) {
		memoryLimit, err := os.ReadFile(filepath.Join(path, "memory.max"))
		if err != nil {
			return fmt.Errorf("read control capacity at %s: %w", path, err)
		}
		limit := strings.TrimSpace(string(memoryLimit))
		if limit == "max" {
			if path == root {
				return errors.New("shared delegation requires finite memory.max for its control reserve")
			}
		} else if available, err := strconv.ParseInt(limit, 10, 64); err != nil || available < memory {
			return fmt.Errorf("memory capacity at %s cannot fit node workers plus control reserve", path)
		}
		cpuLimit, err := os.ReadFile(filepath.Join(path, "cpu.max"))
		if err != nil {
			return fmt.Errorf("read control capacity at %s: %w", path, err)
		}
		fields := strings.Fields(string(cpuLimit))
		if len(fields) != 2 {
			return fmt.Errorf("invalid cpu.max at %s", path)
		}
		period, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || period <= 0 {
			return fmt.Errorf("invalid CPU period at %s", path)
		}
		if fields[0] == "max" {
			if path == root {
				return errors.New("shared delegation requires finite cpu.max for its control reserve")
			}
			continue
		}
		quota, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || quota <= 0 {
			return fmt.Errorf("invalid CPU quota at %s", path)
		}
		// Compare rational CPU capacity exactly across different periods without
		// truncation or overflowing either product of valid int64 limits.
		need := new(big.Int).Mul(big.NewInt(cpu), big.NewInt(period))
		have := new(big.Int).Mul(big.NewInt(quota), big.NewInt(100000))
		if need.Cmp(have) > 0 {
			return fmt.Errorf("CPU capacity at %s cannot fit node workers plus control reserve", path)
		}
	}
	return nil
}
