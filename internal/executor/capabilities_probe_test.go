// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"errors"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/hostprobe"
)

func TestICMPReport(t *testing.T) {
	calls := 0
	probe := func(reason string, err error) func() (string, error) {
		return func() (string, error) { calls++; return reason, err }
	}
	if got := icmpReport(false, probe("", nil)); got.GetState() != "unavailable" || got.GetReason() != netpolicy.ICMPDisabled || calls != 0 {
		t.Fatalf("disabled: %v, %d probes", got, calls)
	}
	if got := icmpReport(true, probe("", nil)); got.GetState() != "available" || got.GetReason() != "" {
		t.Fatalf("available: %v", got)
	}
	if got := icmpReport(true, probe(netpolicy.ICMPPingSocketOnly, errors.New("denied"))); got.GetState() != "unavailable" || got.GetReason() != netpolicy.ICMPPingSocketOnly {
		t.Fatalf("ping only: %v", got)
	}
	if got := icmpReport(true, probe("", errors.New("odd"))); got.GetReason() != netpolicy.ICMPUnsupported {
		t.Fatalf("reasonless failure: %v", got)
	}
}

func TestClockAndPlatformReports(t *testing.T) {
	est, max := 3*time.Millisecond, 40*time.Millisecond
	c := clockState(hostprobe.Clock{State: hostprobe.ClockSynced, EstimatedError: &est, MaxError: &max, Bound: 100 * time.Millisecond, Readiness: hostprobe.ReadinessReady})
	if c.GetState() != "synced" || c.GetEstimatedErrorNs() != 3e6 || c.GetMaxErrorNs() != 40e6 || c.GetErrorBoundNs() != 100e6 || c.GetReadiness() != "ready" || c.GetReason() != "" {
		t.Fatalf("clock: %v", c)
	}
	if c := clockState(hostprobe.Clock{State: hostprobe.ClockUnsynced, Bound: time.Second, Readiness: hostprobe.ReadinessDegraded, Reason: hostprobe.ReasonUnsynced}); c.EstimatedErrorNs != nil || c.MaxErrorNs != nil || c.GetReason() != "unsynced" {
		t.Fatalf("unsynced clock: %v", c)
	}
	p := platformReport(hostprobe.Platform{OS: "linux", Arch: "amd64", KernelRelease: "6.8.0", CPUs: 4, MemoryBytes: 1 << 30, BuildVersion: "0.3.0"})
	if p.GetOs() != "linux" || p.GetCpus() != 4 || p.GetMemoryBytes() != 1<<30 || p.GetKernelRelease() != "6.8.0" || p.GetBuildVersion() != "0.3.0" {
		t.Fatalf("platform: %v", p)
	}
	if p := platformReport(hostprobe.Platform{}); p.MemoryBytes != nil || p.GetCpus() != 0 {
		t.Fatalf("unknown platform: %v", p)
	}
}

// Each capability report carries fresh probes, graded against the configured
// clock bound, and a configured fallback says so.
func TestCapabilityReportCarriesProbes(t *testing.T) {
	cfg := fixtureConfig()
	cfg.Network.PacketCounter = "fallback"
	cfg.Clock.MaxErrorMS = 250
	e := newFixtureExecutor(t, cfg, nil, newFixtureMemoryStorage(t))
	resp, err := e.OnHello(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	caps, vantage := resp.GetCapabilities(), resp.GetVantagePoint()
	if caps.GetEnforcementMode() != "fallback" || caps.GetEnforcementReason() != ratelimit.FallbackConfigured {
		t.Fatalf("enforcement: %v", caps)
	}
	icmp := caps.GetIcmp()
	if icmp == nil || (icmp.GetState() == "available") != slices.Contains(caps.GetProtocols(), "icmp") || resp.GetIcmpEnabled() != (icmp.GetState() == "available") {
		t.Fatalf("icmp %v disagrees with protocols %v or hello %v", icmp, caps.GetProtocols(), resp.GetIcmpEnabled())
	}
	if (icmp.GetState() == "available") != (netpolicy.ICMPPermitted() == nil) {
		t.Fatal("probe disagrees with guest admission")
	}
	clock := vantage.GetClock()
	if clock.GetErrorBoundNs() != int64(250*time.Millisecond) || clock.GetState() == "" || clock.GetReadiness() == "" {
		t.Fatalf("clock: %v", clock)
	}
	if runtime.GOOS != "linux" && clock.GetState() != "unknown" {
		t.Fatalf("non-Linux clock: %v", clock)
	}
	if p := vantage.GetPlatform(); p.GetOs() != runtime.GOOS || p.GetArch() != runtime.GOARCH || p.GetCpus() == 0 {
		t.Fatalf("platform: %v", p)
	}
}
