//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"errors"
	"io/fs"
)

func recoveryDirectoryOwned(fs.FileInfo) error {
	return errors.New("account recovery requires a supported Unix host")
}
