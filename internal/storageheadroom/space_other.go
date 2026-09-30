//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package storageheadroom

import "errors"

func availableBytes(string) (uint64, error) {
	return 0, errors.New("storage headroom is supported on Linux and macOS")
}
