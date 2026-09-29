// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func goodClock() *pb.ClockState {
	return &pb.ClockState{State: "synced", EstimatedErrorNs: i64(2e6), MaxErrorNs: i64(40e6), ErrorBoundNs: 100e6, Readiness: "ready"}
}

func goodPlatform() *pb.HostPlatform {
	memory := uint64(8 << 30)
	return &pb.HostPlatform{Os: "linux", Arch: "amd64", KernelRelease: "6.8.0-45-generic", Cpus: 8, MemoryBytes: &memory, BuildVersion: "0.3.0"}
}

func TestClockReportValidation(t *testing.T) {
	for _, report := range []*pb.ClockState{
		goodClock(),
		{State: "synced", EstimatedErrorNs: i64(150e6), MaxErrorNs: i64(200e6), ErrorBoundNs: 100e6, Readiness: "degraded", Reason: "error_exceeds_bound"},
		{State: "unsynced", ErrorBoundNs: 100e6, Readiness: "degraded", Reason: "unsynced"},
		{State: "unknown", ErrorBoundNs: 100e6, Readiness: "unknown"},
	} {
		got := clockFromReport(report)
		if got == nil || got.State != report.State || got.Readiness != report.Readiness || got.Reason != report.Reason || got.ErrorBoundNS != report.ErrorBoundNs {
			t.Errorf("valid clock refused: %v -> %+v", report, got)
		}
	}
	change := func(f func(*pb.ClockState)) *pb.ClockState { c := goodClock(); f(c); return c }
	for name, report := range map[string]*pb.ClockState{
		"unknown state":       change(func(c *pb.ClockState) { c.State = "drifting" }),
		"no bound":            change(func(c *pb.ClockState) { c.ErrorBoundNs = 0 }),
		"huge bound":          change(func(c *pb.ClockState) { c.ErrorBoundNs = int64(time.Hour) }),
		"negative error":      change(func(c *pb.ClockState) { c.EstimatedErrorNs = i64(-1) }),
		"absurd error":        change(func(c *pb.ClockState) { c.MaxErrorNs = i64(int64(2 * time.Hour)) }),
		"ready above bound":   change(func(c *pb.ClockState) { c.EstimatedErrorNs = i64(101e6) }),
		"degraded in bound":   change(func(c *pb.ClockState) { c.Readiness, c.Reason = "degraded", "error_exceeds_bound" }),
		"ready with reason":   change(func(c *pb.ClockState) { c.Reason = "unsynced" }),
		"unsynced with error": {State: "unsynced", EstimatedErrorNs: i64(1), ErrorBoundNs: 100e6, Readiness: "degraded", Reason: "unsynced"},
		"unsynced ready":      {State: "unsynced", ErrorBoundNs: 100e6, Readiness: "ready"},
		"unknown degraded":    {State: "unknown", ErrorBoundNs: 100e6, Readiness: "degraded", Reason: "unsynced"},
	} {
		if got := clockFromReport(report); got != nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
}

func TestPlatformReportValidation(t *testing.T) {
	got := platformFromReport(goodPlatform())
	if got == nil || *got.OS != "linux" || *got.Arch != "amd64" || *got.KernelRelease != "6.8.0-45-generic" || *got.CPUs != 8 || *got.MemoryBytes != 8<<30 || *got.BuildVersion != "0.3.0" {
		t.Fatalf("valid platform: %+v", got)
	}
	if empty := platformFromReport(&pb.HostPlatform{}); empty == nil || *empty != (wire.HostPlatform{}) {
		t.Fatalf("empty platform must be known-empty: %+v", empty)
	}
	change := func(f func(*pb.HostPlatform)) *pb.HostPlatform { p := goodPlatform(); f(p); return p }
	zero := uint64(0)
	for name, report := range map[string]*pb.HostPlatform{
		"upper-case os":    change(func(p *pb.HostPlatform) { p.Os = "Linux" }),
		"control in arch":  change(func(p *pb.HostPlatform) { p.Arch = "amd64\n" }),
		"space in release": change(func(p *pb.HostPlatform) { p.KernelRelease = "6.8 generic" }),
		"long release":     change(func(p *pb.HostPlatform) { p.KernelRelease = string(make([]byte, 129)) }),
		"non-ascii build":  change(func(p *pb.HostPlatform) { p.BuildVersion = "0.3.0-é" }),
		"too many cpus":    change(func(p *pb.HostPlatform) { p.Cpus = 1<<16 + 1 }),
		"zero memory":      change(func(p *pb.HostPlatform) { p.MemoryBytes = &zero }),
	} {
		if got := platformFromReport(report); got != nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
}

// A malformed probe field leaves only that field unknown: the network facts of
// the same report stay published and the node stays listed.
func TestMalformedProbeFieldKeepsReport(t *testing.T) {
	bad := goodClock()
	bad.Readiness = "perfect"
	platform := goodPlatform()
	platform.Os = "LINUX"
	got := vantageFromReport(&pb.VantagePointReport{SchemaVersion: 1, ScionIsdAs: "1-ff00:0:110", Listeners: []string{"udp"}, Clock: bad, Platform: platform})
	if got == nil || got.isdAS != "1-ff00:0:110" || len(got.listeners) != 1 || got.clock != nil || got.platform != nil {
		t.Fatalf("report: %+v", got)
	}
	got = vantageFromReport(&pb.VantagePointReport{SchemaVersion: 1, Clock: goodClock(), Platform: goodPlatform()})
	if got == nil || got.clock == nil || got.platform == nil {
		t.Fatalf("valid probes dropped: %+v", got)
	}
}

func TestCapabilityProbeFieldValidation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, tc := range []struct {
		name       string
		report     *pb.ExecutorCapabilities
		wantICMP   *wire.ProbeState
		wantReason string
	}{
		{"available", &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"icmp"}, EnforcementMode: "fallback", EnforcementReason: "not_permitted", Icmp: &pb.ProbeState{State: "available"}},
			&wire.ProbeState{State: "available"}, "not_permitted"},
		{"unavailable", &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, EnforcementMode: "fallback", EnforcementReason: "configured", Icmp: &pb.ProbeState{State: "unavailable", Reason: "ping_socket_only"}},
			&wire.ProbeState{State: "unavailable", Reason: "ping_socket_only"}, "configured"},
		{"reason with ebpf", &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{}, EnforcementMode: "ebpf", EnforcementReason: "configured"}, nil, ""},
		{"unknown reason", &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{}, EnforcementMode: "fallback", EnforcementReason: "because"}, nil, ""},
		{"available without protocol", &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, Icmp: &pb.ProbeState{State: "available"}}, nil, ""},
		{"unavailable with protocol", &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"icmp"}, Icmp: &pb.ProbeState{State: "unavailable", Reason: "disabled"}}, nil, ""},
		{"unavailable without reason", &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{}, Icmp: &pb.ProbeState{State: "unavailable"}}, nil, ""},
		{"available with reason", &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"icmp"}, Icmp: &pb.ProbeState{State: "available", Reason: "disabled"}}, nil, ""},
	} {
		got := capabilitiesFromReport(tc.report, now)
		if got == nil {
			t.Errorf("%s: a bad probe field discarded the capabilities", tc.name)
			continue
		}
		if (got.ICMP == nil) != (tc.wantICMP == nil) || got.ICMP != nil && *got.ICMP != *tc.wantICMP || got.EnforcementReason != tc.wantReason {
			t.Errorf("%s: icmp %+v reason %q", tc.name, got.ICMP, got.EnforcementReason)
		}
		if len(got.Protocols) != len(tc.report.Protocols) || got.EnforcementMode != tc.report.EnforcementMode {
			t.Errorf("%s: other fields changed: %+v", tc.name, got)
		}
	}
}

// The clock is live and public; the platform is only in the admission
// snapshot, both labelled executor-reported and marked stale once expired.
func TestProbeObservationsLiveAndAdmission(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	now := time.Unix(1700000000, 0)
	d.now = func() time.Time { return now }
	owner := registryOwner(t, "probed")
	hello := registryHello("probed")
	hello.Capabilities = &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{}, EnforcementMode: "fallback", EnforcementReason: "no_interface",
		Icmp: &pb.ProbeState{State: "unavailable", Reason: "not_permitted"}}
	hello.VantagePoint = &pb.VantagePointReport{SchemaVersion: 1, Clock: goodClock(), Platform: goodPlatform()}
	if err := registryRegisterWithSetup(t.Context(), d, owner, hello, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	owner.MarkRegistered()
	snapshot, ok := d.GetExecutor("probed")
	if !ok {
		t.Fatal("registration missing")
	}
	clock := snapshot.Clock()
	if clock.Value == nil || clock.Value.State != "synced" || *clock.Value.EstimatedErrorNS != 2e6 || *clock.Source != wire.SourceExecutorReported || *clock.ObservedAt != now.Unix() {
		t.Fatalf("live clock: %+v", clock)
	}
	if c := snapshot.Capabilities; c == nil || c.EnforcementReason != "no_interface" || c.ICMP == nil || c.ICMP.Reason != "not_permitted" {
		t.Fatalf("live capabilities: %+v", c)
	}

	now = now.Add(capabilityLifetime)
	if snapshot, _ := d.GetExecutor("probed"); snapshot.Clock() != (wire.ObservedClock{}) {
		t.Fatal("expired clock stayed live")
	}
	d.mu.Lock()
	v := admissionVantagePoint(d.executors["probed"], d.now())
	d.mu.Unlock()
	if v.Clock.Value == nil || !*v.Clock.Stale || *v.Clock.Source != wire.SourceExecutorReported || v.Clock.Value.Readiness != "ready" {
		t.Fatalf("admission clock: %+v", v.Clock)
	}
	if v.Platform.Value == nil || !*v.Platform.Stale || *v.Platform.Value.OS != "linux" || *v.Platform.Source != wire.SourceExecutorReported {
		t.Fatalf("admission platform: %+v", v.Platform)
	}
	if c := v.Capabilities.Value; c == nil || c.EnforcementReason != "no_interface" || c.ICMP == nil || c.ICMP.State != "unavailable" {
		t.Fatalf("admission capabilities: %+v", c)
	}
}
