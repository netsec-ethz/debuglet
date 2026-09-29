// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package hostprobe

import "golang.org/x/sys/unix"

func kernelRelease() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}

func totalMemory() uint64 {
	var info unix.Sysinfo_t
	if unix.Sysinfo(&info) != nil {
		return 0
	}
	unit := uint64(info.Unit)
	if unit == 0 {
		unit = 1
	}
	return uint64(info.Totalram) * unit
}
