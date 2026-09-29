// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux && !darwin

package hostprobe

func kernelRelease() string { return "" }
func totalMemory() uint64   { return 0 }
