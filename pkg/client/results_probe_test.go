// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// The probe fields were added within vantage_point schema 1: the fixture,
// written before them, reads with them null, and a file that carries them
// round-trips and is validated.
func TestResultVantagePointProbes(t *testing.T) {
	label := func(s string) *string { return &s }
	doc := currentResultFixture(t)
	v := doc.Provenance.VantagePoint
	if v.Clock != (wire.LabelledReport[wire.ClockReport]{}) || v.Platform != (wire.LabelledReport[wire.HostPlatform]{}) {
		t.Fatalf("earlier 1.1 file: %+v", v)
	}
	if c := v.Capabilities.Value; c != nil && (c.ICMP != nil || c.EnforcementReason != "") {
		t.Fatalf("earlier 1.1 capabilities: %+v", c)
	}
	observed, stale, est, cpus := time.Date(2026, 9, 28, 11, 58, 40, 0, time.UTC), false, int64(2e6), int64(8)
	with := func(t *testing.T) Result {
		doc := currentResultFixture(t)
		v := doc.Provenance.VantagePoint
		v.Clock = wire.LabelledReport[wire.ClockReport]{Value: &wire.ClockReport{State: "synced", EstimatedErrorNS: &est, ErrorBoundNS: 100e6, Readiness: "ready"},
			Source: label(wire.SourceExecutorReported), ObservedAt: &observed, Stale: &stale}
		v.Platform = wire.LabelledReport[wire.HostPlatform]{Value: &wire.HostPlatform{OS: label("linux"), CPUs: &cpus},
			Source: label(wire.SourceExecutorReported), ObservedAt: &observed, Stale: &stale}
		if c := v.Capabilities.Value; c != nil {
			c.EnforcementMode, c.EnforcementReason = "fallback", "no_interface"
			c.ICMP = &wire.ProbeState{State: "unavailable", Reason: "not_permitted"}
		}
		return doc
	}
	doc = with(t)
	if doc.Provenance.VantagePoint.Capabilities.Value == nil {
		t.Fatal("fixture has no capability report")
	}
	data, _ := json.Marshal(doc)
	if again, err := ReadResult(bytes.NewReader(data)); err != nil || !reflect.DeepEqual(again, doc) {
		t.Fatalf("roundtrip: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*wire.VantagePoint)
	}{
		{"clock without source", func(v *wire.VantagePoint) { v.Clock.Source = nil }},
		{"clock without staleness", func(v *wire.VantagePoint) { v.Clock.Stale = nil }},
		{"orphan clock label", func(v *wire.VantagePoint) { v.Clock.Value = nil }},
		{"unknown clock state", func(v *wire.VantagePoint) { v.Clock.Value.State = "atomic" }},
		{"degraded without reason", func(v *wire.VantagePoint) { v.Clock.Value.Readiness = "degraded" }},
		{"no clock bound", func(v *wire.VantagePoint) { v.Clock.Value.ErrorBoundNS = 0 }},
		{"verified platform", func(v *wire.VantagePoint) { v.Platform.Source = label("verified") }},
		{"undated platform", func(v *wire.VantagePoint) { v.Platform.ObservedAt = nil }},
		{"reason with ebpf", func(v *wire.VantagePoint) { v.Capabilities.Value.EnforcementMode = "ebpf" }},
		{"unknown fallback reason", func(v *wire.VantagePoint) { v.Capabilities.Value.EnforcementReason = "whim" }},
		{"icmp without reason", func(v *wire.VantagePoint) { v.Capabilities.Value.ICMP.Reason = "" }},
		{"available icmp with reason", func(v *wire.VantagePoint) { v.Capabilities.Value.ICMP.State = "available" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := with(t)
			tc.change(doc.Provenance.VantagePoint)
			data, _ := json.Marshal(doc)
			if _, err := ReadResult(bytes.NewReader(data)); err == nil {
				t.Fatal("accepted invalid vantage point")
			}
		})
	}
}
