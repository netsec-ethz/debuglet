// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package hostprobe

import (
	"runtime"

	"github.com/netsec-ethz/debuglet/internal/buildinfo"
)

// Platform describes the host an executor runs on. Empty and zero values are
// unknown. It is operator-only data: the dispatcher never lists it publicly.
type Platform struct {
	OS            string
	Arch          string
	KernelRelease string
	CPUs          int
	MemoryBytes   uint64
	BuildVersion  string
}

// ReadPlatform reads the platform facts. It never fails; a fact that cannot be
// read is left unknown.
func ReadPlatform() Platform {
	return Platform{
		OS: runtime.GOOS, Arch: runtime.GOARCH, KernelRelease: kernelRelease(),
		CPUs: runtime.NumCPU(), MemoryBytes: totalMemory(), BuildVersion: buildinfo.Version,
	}
}
