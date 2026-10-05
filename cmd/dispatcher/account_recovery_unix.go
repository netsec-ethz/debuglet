//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func recoveryDirectoryOwned(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(os.Geteuid()) {
		return errors.New("recovery output parent must be owned by the current user")
	}
	return nil
}
