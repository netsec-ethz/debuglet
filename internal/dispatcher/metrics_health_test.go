// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"crypto/sha256"
	"math"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
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

// TestMetricsDisclosureLagFollowsVerifiedKeys drives a real key store with a
// real hash chain of ten 10-second epochs and a disclosure delay of two: k_i
// becomes disclosable at start+(i+2)*10s. The dispatcher clock is now.
func TestMetricsDisclosureLagFollowsVerifiedKeys(t *testing.T) {
	const length = 10
	keys := make([][]byte, length)
	keys[length-1] = bytes.Repeat([]byte{0x4C}, 32)
	for i := length - 2; i >= 0; i-- {
		sum := sha256.Sum256(keys[i+1])
		keys[i] = sum[:]
	}
	start := time.Unix(10000, 0)
	ks := tag.NewKeyStore()
	e := &executorEntry{RegisteredExecutor: &RegisteredExecutor{ID: "lagging", TeslaAnchorKey: keys[0], TeslaAnchorTimestamp: start,
		TeslaDelay: 10 * time.Second, TeslaDisclosureDelay: 2, TeslaChainLength: length}}
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	lag := func(now time.Time, connected bool) ExecutorResourceMetric {
		t.Helper()
		e.capabilityObserved = now.Add(-time.Second)
		var h ExecutorHealthMetrics
		h.observeDisclosureLag(e, now, connected, ks)
		return h.DisclosureLag
	}
	want := func(name string, got ExecutorResourceMetric, seconds float64) {
		t.Helper()
		if got.Unknown != 0 || got.Value == nil || *got.Value != seconds {
			t.Fatalf("%s: lag %+v, want %v s", name, got, seconds)
		}
	}
	unknown := func(name string, got ExecutorResourceMetric) {
		t.Helper()
		if got.Unknown != 1 || got.Value != nil {
			t.Fatalf("%s: lag %+v, want unknown", name, got)
		}
	}
	disclose := func(now time.Time, epoch int) {
		t.Helper()
		if err := ks.Store(e.ID, e.teslaChain(), now, int64(epoch), keys[epoch]); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing is due before start+30s, whether or not a key arrived.
	want("nothing due", lag(at(29), true), 0)
	unknown("first key due but none received", lag(at(35), true))
	disclose(at(35), 1)
	want("all due keys stored", lag(at(35), true), 0)
	// At start+67s k_4 is due; k_2 has been disclosable since start+40s.
	want("due keys missing", lag(at(67), true), 27)
	unknown("disconnected session", lag(at(67), false))
	e.capabilityObserved = at(67).Add(-capabilityLifetime)
	var stale ExecutorHealthMetrics
	stale.observeDisclosureLag(e, at(67), true, ks)
	unknown("stale report", stale.DisclosureLag)
	disclose(at(67), 4)
	want("caught up", lag(at(67), true), 0)
	// Past the chain's end only k_9 is due, disclosable from start+110s.
	want("chain end missing", lag(at(3600), true), 3600-70)
	disclose(at(3600), length-1)
	want("chain end", lag(at(3600), true), 0)

	// The aggregate is the maximum, and any unknown executor is counted.
	other := &executorEntry{RegisteredExecutor: &RegisteredExecutor{ID: "other", TeslaAnchorKey: []byte("unseen"), TeslaAnchorTimestamp: start,
		TeslaDelay: 10 * time.Second, TeslaDisclosureDelay: 2, TeslaChainLength: length, capabilityObserved: at(3599)}}
	e.TeslaChainLength = 2 * length
	e.capabilityObserved = at(3599)
	var h ExecutorHealthMetrics
	h.observeDisclosureLag(e, at(3600), true, ks)
	h.observeDisclosureLag(other, at(3600), true, ks)
	if h.DisclosureLag.Unknown != 1 || h.DisclosureLag.Value == nil || *h.DisclosureLag.Value != 3600-120 {
		t.Fatalf("aggregate: %+v", h.DisclosureLag)
	}
	e.TeslaChainLength = length

	for name, edit := range map[string]func(*RegisteredExecutor){
		"no epoch length": func(r *RegisteredExecutor) { r.TeslaDelay = 0 },
		"no chain length": func(r *RegisteredExecutor) { r.TeslaChainLength = 0 },
		"no anchor":       func(r *RegisteredExecutor) { r.TeslaAnchorKey = nil },
		"no start":        func(r *RegisteredExecutor) { r.TeslaAnchorTimestamp = time.Time{} },
	} {
		saved := *e.RegisteredExecutor
		edit(e.RegisteredExecutor)
		unknown(name, lag(at(67), true))
		*e.RegisteredExecutor = saved
	}
}

// TestCollectMetricsReportsDisclosureLagFromTheKeyStore checks the scrape path:
// the dispatcher's own key store answers, and a recorded key ends the unknown.
func TestCollectMetricsReportsDisclosureLagFromTheKeyStore(t *testing.T) {
	f := newTGFixture(t, nil)
	tail := bytes.Repeat([]byte{0x4D}, 32)
	sum := sha256.Sum256(tail)
	now := time.Now()
	f.d.mu.Lock()
	e := f.d.executors[tgExecutorID]
	// k_1 has been due since the start of epoch 3, about five seconds ago.
	e.TeslaAnchorKey, e.TeslaAnchorTimestamp, e.TeslaDelay, e.TeslaDisclosureDelay, e.TeslaChainLength = sum[:], now.Add(-35*time.Second), 10*time.Second, 2, 2
	e.capabilityObserved = now
	chain := e.teslaChain()
	f.d.mu.Unlock()
	if lag := f.d.CollectMetrics(f.ctx).Health.DisclosureLag; lag.Unknown != 1 || lag.Value != nil {
		t.Fatalf("before any disclosure: %+v", lag)
	}
	if err := f.d.keystore.Store(tgExecutorID, chain, time.Now(), 1, tail); err != nil {
		t.Fatal(err)
	}
	if lag := f.d.CollectMetrics(f.ctx).Health.DisclosureLag; lag.Unknown != 0 || lag.Value == nil || *lag.Value != 0 {
		t.Fatalf("after the due key was recorded: %+v", lag)
	}
}
