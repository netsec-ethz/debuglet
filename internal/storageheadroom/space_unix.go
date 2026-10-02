//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package storageheadroom

import (
	"golang.org/x/sys/unix"
	"math"
)

func availableBytes(path string) (uint64, error) {
	var state unix.Statfs_t
	if err := unix.Statfs(path, &state); err != nil {
		return 0, err
	}
	size := uint64(state.Bsize)
	if size == 0 {
		return 0, nil
	}
	if uint64(state.Bavail) > math.MaxUint64/size {
		return math.MaxUint64, nil
	}
	return uint64(state.Bavail) * size, nil
}
