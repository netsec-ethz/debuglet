// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package hostprobe reads host facts an executor reports about itself: the
// kernel clock discipline and the host platform. Every probe is read-only and
// local; none changes host state, contacts a time source or sends a packet.
package hostprobe

import "time"

// Clock states.
const (
	ClockSynced   = "synced"
	ClockUnsynced = "unsynced"
	ClockUnknown  = "unknown"
)

// Clock readiness and its degraded reasons.
const (
	ReadinessReady    = "ready"
	ReadinessDegraded = "degraded"
	ReadinessUnknown  = "unknown"

	ReasonUnsynced          = "unsynced"
	ReasonErrorExceedsBound = "error_exceeds_bound"
)

// DefaultClockErrorBound is the estimated clock error above which an executor
// reports its clock readiness as degraded unless the operator configures a
// different bound.
const DefaultClockErrorBound = 100 * time.Millisecond

// Clock is the kernel's view of its own clock discipline. EstimatedError and
// MaxError are the kernel's esterror and maxerror, maintained by a time daemon
// such as chrony or ntpd; they are estimates, not measured bounds.
type Clock struct {
	State          string
	EstimatedError *time.Duration
	MaxError       *time.Duration
	Bound          time.Duration
	Readiness      string
	Reason         string
}

// ReadClock reads the kernel clock state and grades it against bound. A
// non-positive bound uses DefaultClockErrorBound.
func ReadClock(bound time.Duration) Clock {
	if bound <= 0 {
		bound = DefaultClockErrorBound
	}
	c := readKernelClock()
	c.Bound = bound
	c.Readiness, c.Reason = grade(c)
	return c
}

func grade(c Clock) (string, string) {
	switch c.State {
	case ClockUnsynced:
		return ReadinessDegraded, ReasonUnsynced
	case ClockSynced:
		if c.EstimatedError == nil {
			return ReadinessUnknown, ""
		}
		if *c.EstimatedError > c.Bound {
			return ReadinessDegraded, ReasonErrorExceedsBound
		}
		return ReadinessReady, ""
	default:
		return ReadinessUnknown, ""
	}
}
