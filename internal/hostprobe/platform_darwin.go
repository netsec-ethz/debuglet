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
	memory, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return memory
}
