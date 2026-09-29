// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"strings"
	"testing"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"
)

func i64(v int64) *int64 { return &v }

// A valid attribution state is converted to dispatcher-clock times; a report
// without one keeps attribution unknown; any malformed state clears the whole
// report, like a malformed protocol list.
func TestCapabilityAttributionValidation(t *testing.T) {
	observed := time.Unix(1700000000, 0)
	report := func(a *pb.AttributionState) *pb.ExecutorCapabilities {
		return &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, EnforcementMode: "ebpf", Attribution: a}
	}
	if got := capabilitiesFromReport(report(nil), observed); got == nil || got.Attribution != nil {
		t.Fatalf("older executor: %+v", got)
	}
	held := &pb.AttributionState{State: "unavailable", Reason: "disclosure_held", Epoch: 9,
		InstalledEpoch: i64(7), LastRefreshAgeMs: i64(25_000), DisclosureHeldMs: i64(12_500)}
	got := capabilitiesFromReport(report(held), observed)
	if got == nil || got.Attribution == nil {
		t.Fatal("valid held report refused")
	}
	if a := got.Attribution; a.State != "unavailable" || a.Reason != "disclosure_held" || a.Epoch != 9 || *a.InstalledEpoch != 7 ||
		*a.LastRefreshAt != observed.Unix()-25 || *a.DisclosureHeldSince != observed.Unix()-13 || a.RefreshError != "" {
		t.Fatalf("held report: %+v", a)
	}
	for _, valid := range []*pb.AttributionState{
		{State: "available", Epoch: 1},
		{State: "unavailable", Reason: "epoch_zero"},
		{State: "unavailable", Reason: "chain_exhausted", Epoch: 64},
		{State: "unavailable", Reason: "refresh_failing", Epoch: 3, RefreshError: "stale key remains installed: " + strings.Repeat("é", 40)},
	} {
		if got := capabilitiesFromReport(report(valid), observed); got == nil || got.Attribution == nil || got.Attribution.State != valid.State {
			t.Errorf("valid %v refused", valid)
		}
	}
	for name, invalid := range map[string]*pb.AttributionState{
		"empty state":             {},
		"unknown state":           {State: "maybe"},
		"available with reason":   {State: "available", Reason: "epoch_zero", Epoch: 1},
		"unavailable no reason":   {State: "unavailable", Epoch: 1},
		"unknown reason":          {State: "unavailable", Reason: "clock_skew", Epoch: 1},
		"negative epoch":          {State: "available", Epoch: -1},
		"installed after current": {State: "available", Epoch: 2, InstalledEpoch: i64(3)},
		"negative installed":      {State: "available", Epoch: 2, InstalledEpoch: i64(-1)},
		"negative age":            {State: "available", Epoch: 2, LastRefreshAgeMs: i64(-1)},
		"overflowing age":         {State: "available", Epoch: 2, LastRefreshAgeMs: i64(1 << 62)},
		"negative hold":           {State: "available", Epoch: 2, DisclosureHeldMs: i64(-1)},
		"failing without error":   {State: "unavailable", Reason: "refresh_failing", Epoch: 2},
		"held without hold":       {State: "unavailable", Reason: "disclosure_held", Epoch: 2},
		"long error":              {State: "unavailable", Reason: "refresh_failing", Epoch: 2, RefreshError: strings.Repeat("x", 129)},
		"invalid utf-8 error":     {State: "unavailable", Reason: "refresh_failing", Epoch: 2, RefreshError: "\xff"},
		"control in error":        {State: "unavailable", Reason: "refresh_failing", Epoch: 2, RefreshError: "a\nb"},
	} {
		if got := capabilitiesFromReport(report(invalid), observed); got != nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
}
