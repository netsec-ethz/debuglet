// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package hostprobe

// Only Linux exposes the kernel clock discipline through adjtimex.
func readKernelClock() Clock { return Clock{State: ClockUnknown} }
