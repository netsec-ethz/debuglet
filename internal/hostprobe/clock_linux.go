// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package hostprobe

import (
	"time"

	"golang.org/x/sys/unix"
)

// readKernelClock calls adjtimex with no mode bits, which only reads the
// kernel's state and needs no privilege. The kernel reports an unsynchronised
// clock through STA_UNSYNC or the TIME_ERROR return value; its error estimates
// are then not maintained and are left unknown.
func readKernelClock() Clock {
	var tx unix.Timex // Modes 0: read only.
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return Clock{State: ClockUnknown}
	}
	if state == unix.TIME_ERROR || tx.Status&unix.STA_UNSYNC != 0 {
		return Clock{State: ClockUnsynced}
	}
	estimated := time.Duration(int64(tx.Esterror)) * time.Microsecond
	maximum := time.Duration(int64(tx.Maxerror)) * time.Microsecond
	return Clock{State: ClockSynced, EstimatedError: &estimated, MaxError: &maximum}
}
