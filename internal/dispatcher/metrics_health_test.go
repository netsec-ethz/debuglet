// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"math"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestMetricsHealthUsesFreshReportsAndExpiresWithoutHeartbeat(t *testing.T) {
	f := newTGFixture(t, nil)
	observed := time.Now().UTC()
	capabilities := &pb.ExecutorCapabilities{SchemaVersion: 1, EnforcementMode: "ebpf", Attribution: &pb.AttributionState{State: "available", Epoch: 2}}
	estimate := int64(2 * time.Millisecond)
	clock := &pb.ClockState{State: "synced", Readiness: "ready", ErrorBoundNs: int64(time.Second), EstimatedErrorNs: &estimate}
	set := func(at time.Time) {
		f.d.mu.Lock()
		defer f.d.mu.Unlock()
		e := f.d.executors[tgExecutorID]
		e.Capabilities, e.capabilityObserved = capabilitiesFromReport(capabilities, at), at
		e.vantage, e.vantageObserved = vantageFromReport(&pb.VantagePointReport{SchemaVersion: 1, Clock: clock}), at
		e.TeslaChainLength, e.TeslaDelay, e.TeslaAnchorTimestamp = 10, time.Minute, observed.Add(-2*time.Minute)
	}
	set(observed)
	h := f.d.CollectMetrics(f.ctx).Health
	if h.EBPF != 1 || h.AttributionAvailable != 1 || h.ClockReady != 1 || h.ScheduleRemainingSeconds == nil || *h.ScheduleRemainingSeconds < 479 || *h.ScheduleRemainingSeconds > 480 || h.ClockEstimatedErrorSeconds == nil || *h.ClockEstimatedErrorSeconds != .002 {
		t.Fatalf("fresh report: %+v", h)
	}
	// A selected fallback is visible, but not automatically a required-mode
	// failure: the collector's policy decides whether fallback is acceptable.
	capabilities.EnforcementMode = "fallback"
	capabilities.EnforcementReason = "not_permitted"
	held := int64(120000)
	capabilities.Attribution = &pb.AttributionState{State: "unavailable", Reason: "disclosure_held", Epoch: 2, DisclosureHeldMs: &held}
	clock.State, clock.Readiness, clock.Reason, clock.EstimatedErrorNs = "unsynced", "degraded", "unsynced", nil
	set(time.Now())
	h = f.d.CollectMetrics(f.ctx).Health
	if h.Fallback != 1 || h.EBPF != 0 || h.DisclosureHeld != 1 || h.DisclosureHeldSeconds < 120 || h.ClockDegraded != 1 || h.ClockEstimatedErrorSeconds != nil {
		t.Fatalf("degraded report: %+v", h)
	}
	set(time.Now().Add(-capabilityLifetime))
	h = f.d.CollectMetrics(f.ctx).Health
	if h.EnforcementUnknown != 1 || h.AttributionUnknown != 1 || h.ClockUnknown != 1 || h.ScheduleUnknown != 1 || h.Fallback != 0 || h.DisclosureHeld != 0 || h.ScheduleRemainingSeconds != nil {
		t.Fatalf("stale reports must become unknown: %+v", h)
	}
	set(time.Now().Add(time.Minute))
	if h = f.d.CollectMetrics(f.ctx).Health; h.EnforcementUnknown != 1 || h.AttributionUnknown != 1 {
		t.Fatalf("future observation must be unknown: %+v", h)
	}
	set(time.Now())
	f.d.mu.RLock()
	owner := f.d.executors[tgExecutorID].owner
	f.d.mu.RUnlock()
	owner.Retire()
	if h = f.d.CollectMetrics(f.ctx).Health; h.EnforcementUnknown != 1 || h.AttributionUnknown != 1 || h.ClockUnknown != 1 {
		t.Fatalf("disconnect must not reuse a fresh positive: %+v", h)
	}
}

func TestMetricsScheduleExpiryAndUnknownArithmetic(t *testing.T) {
	now := time.Unix(10000, 0)
	e := &executorEntry{RegisteredExecutor: &RegisteredExecutor{TeslaAnchorTimestamp: now.Add(-time.Hour), TeslaDelay: time.Minute, TeslaChainLength: 60,
		Capabilities: &wire.ExecutorCapabilities{EnforcementMode: "fallback"}, capabilityObserved: now}}
	var h ExecutorHealthMetrics
	h.observe(e, now, true)
	if h.ScheduleExpired != 1 || h.ScheduleRemainingSeconds == nil || *h.ScheduleRemainingSeconds != 0 {
		t.Fatalf("chain expiry: %+v", h)
	}
	for _, length := range []int64{0, -1, math.MaxInt64} {
		e.TeslaChainLength = length
		h = ExecutorHealthMetrics{}
		h.observe(e, now, true)
		if h.ScheduleUnknown != 1 || h.ScheduleRemainingSeconds != nil || h.ScheduleExpired != 0 {
			t.Fatalf("unknown/overflow length %d: %+v", length, h)
		}
	}
}

// Every validated attribution report lands in exactly one attribution bucket,
// so the buckets partition the registered executors.
func TestMetricsAttributionBucketsPartitionExecutors(t *testing.T) {
	now := time.Unix(10000, 0)
	held := int64(1000)
	reports := []*pb.AttributionState{
		nil,
		{State: "available", Epoch: 2},
		{State: "unavailable", Reason: "epoch_zero"},
		{State: "unavailable", Reason: "chain_exhausted", Epoch: 9},
		{State: "unavailable", Reason: "refresh_failing", Epoch: 2, RefreshError: "put failed"},
		{State: "unavailable", Reason: "disclosure_held", Epoch: 2, DisclosureHeldMs: &held},
		{State: "unavailable", Reason: "clock_unready", Epoch: 2},
		{State: "unavailable", Reason: "clock_drift", Epoch: 2},
	}
	var total ExecutorHealthMetrics
	for _, report := range reports {
		caps := capabilitiesFromReport(&pb.ExecutorCapabilities{SchemaVersion: 1, EnforcementMode: "ebpf", Attribution: report}, now)
		if caps == nil || (report != nil && caps.Attribution == nil) {
			t.Fatalf("report %v refused", report)
		}
		e := &executorEntry{RegisteredExecutor: &RegisteredExecutor{Capabilities: caps, capabilityObserved: now}}
		var one ExecutorHealthMetrics
		one.observe(e, now, true)
		total.observe(e, now, true)
		if n := attributionBuckets(one); n != 1 {
			t.Errorf("report %v counted %d times: %+v", report, n, one)
		}
	}
	if total.ClockUnready != 1 || total.ClockDrift != 1 || attributionBuckets(total) != len(reports) {
		t.Fatalf("aggregate: %+v", total)
	}
}

func attributionBuckets(h ExecutorHealthMetrics) int {
	return h.AttributionAvailable + h.EpochZero + h.ChainExhausted + h.RefreshFailing + h.DisclosureHeld + h.ClockUnready + h.ClockDrift + h.AttributionUnknown
}
