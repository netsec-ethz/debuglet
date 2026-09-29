// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/hostprobe"
)

func TestDoctorClockCheck(t *testing.T) {
	small, large := 2*time.Millisecond, 300*time.Millisecond
	for _, tc := range []struct {
		name   string
		clock  hostprobe.Clock
		status string
		detail string
	}{
		{"ready", hostprobe.Clock{State: hostprobe.ClockSynced, EstimatedError: &small, Bound: 100 * time.Millisecond, Readiness: hostprobe.ReadinessReady}, "pass", "within the 100ms bound"},
		{"unsynced", hostprobe.Clock{State: hostprobe.ClockUnsynced, Bound: 100 * time.Millisecond, Readiness: hostprobe.ReadinessDegraded, Reason: hostprobe.ReasonUnsynced}, "failure", "not synchronized"},
		{"exceeds", hostprobe.Clock{State: hostprobe.ClockSynced, EstimatedError: &large, Bound: 100 * time.Millisecond, Readiness: hostprobe.ReadinessDegraded, Reason: hostprobe.ReasonErrorExceedsBound}, "failure", "300ms exceeds the 100ms bound"},
		{"unknown", hostprobe.Clock{State: hostprobe.ClockUnknown, Bound: 100 * time.Millisecond, Readiness: hostprobe.ReadinessUnknown}, "not_checked", "unavailable on this platform"},
	} {
		check := clockCheck(tc.clock)
		if check.ID != "clock" || check.Status != tc.status || !strings.Contains(check.Detail, tc.detail) {
			t.Errorf("%s: %+v", tc.name, check)
		}
	}
}

// doctor grades the clock against the selected executor's bound, and the
// default without a daemon file.
func TestDoctorClockUsesExecutorBound(t *testing.T) {
	var bounds []time.Duration
	original := readClock
	readClock = func(bound time.Duration) hostprobe.Clock {
		bounds = append(bounds, bound)
		return hostprobe.Clock{State: hostprobe.ClockUnknown, Bound: bound, Readiness: hostprobe.ReadinessUnknown}
	}
	t.Cleanup(func() { readClock = original })

	_, out, _ := runCLI(context.Background(), "--output", outputJSON, "doctor")
	if check := doctorResult(t, out, "clock"); check.Status != "not_checked" {
		t.Fatalf("clock %+v", check)
	}
	file := writeOperatorConfig(t, "executor", "[network]\npacket_counter='fallback'\n[clock]\nmax_error_ms = 25\n")
	_, out, _ = runCLI(context.Background(), "--output", outputJSON, "doctor", "--role", "executor", "--file", file)
	if check := doctorResult(t, out, "config"); check.Status != "pass" {
		t.Fatalf("config %+v", check)
	}
	if len(bounds) != 2 || bounds[0] != hostprobe.DefaultClockErrorBound || bounds[1] != 25*time.Millisecond {
		t.Fatalf("bounds %v", bounds)
	}
}
