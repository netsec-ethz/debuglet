// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package hostprobe

import (
	"runtime"
	"testing"
	"time"
)

func TestGradeClock(t *testing.T) {
	ms := func(n int) *time.Duration { d := time.Duration(n) * time.Millisecond; return &d }
	for _, tc := range []struct {
		name              string
		clock             Clock
		readiness, reason string
	}{
		{"within bound", Clock{State: ClockSynced, EstimatedError: ms(5), Bound: 100 * time.Millisecond}, ReadinessReady, ""},
		{"at bound", Clock{State: ClockSynced, EstimatedError: ms(100), Bound: 100 * time.Millisecond}, ReadinessReady, ""},
		{"above bound", Clock{State: ClockSynced, EstimatedError: ms(101), Bound: 100 * time.Millisecond}, ReadinessDegraded, ReasonErrorExceedsBound},
		{"unsynced", Clock{State: ClockUnsynced, Bound: time.Second}, ReadinessDegraded, ReasonUnsynced},
		{"unknown", Clock{State: ClockUnknown, Bound: time.Second}, ReadinessUnknown, ""},
		{"synced without estimate", Clock{State: ClockSynced, Bound: time.Second}, ReadinessUnknown, ""},
	} {
		if readiness, reason := grade(tc.clock); readiness != tc.readiness || reason != tc.reason {
			t.Errorf("%s: got %s/%s, want %s/%s", tc.name, readiness, reason, tc.readiness, tc.reason)
		}
	}
}

// The real read must be self-consistent whatever the host's clock state is.
func TestReadClockIsConsistent(t *testing.T) {
	c := ReadClock(0)
	if c.Bound != DefaultClockErrorBound {
		t.Fatalf("default bound: %v", c.Bound)
	}
	switch c.State {
	case ClockSynced:
		if c.EstimatedError == nil || *c.EstimatedError < 0 || c.MaxError == nil || *c.MaxError < 0 {
			t.Fatalf("synced clock without estimates: %+v", c)
		}
	case ClockUnsynced, ClockUnknown:
		if c.EstimatedError != nil || c.MaxError != nil {
			t.Fatalf("%s clock with estimates: %+v", c.State, c)
		}
	default:
		t.Fatalf("state %q", c.State)
	}
	if runtime.GOOS != "linux" && c.State != ClockUnknown {
		t.Fatalf("non-Linux clock state %q", c.State)
	}
	if want, _ := grade(c); c.Readiness != want {
		t.Fatalf("readiness %q, want %q", c.Readiness, want)
	}
}

func TestReadPlatform(t *testing.T) {
	p := ReadPlatform()
	if p.OS != runtime.GOOS || p.Arch != runtime.GOARCH || p.CPUs != runtime.NumCPU() || p.CPUs < 1 {
		t.Fatalf("platform %+v", p)
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if p.KernelRelease == "" || p.MemoryBytes == 0 {
			t.Fatalf("kernel release or memory unknown: %+v", p)
		}
	}
}
