// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"testing"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestMetricsDisclosureCompletionExpiresActualSample(t *testing.T) {
	now := time.Now()
	anchor := bytes.Repeat([]byte{1}, 32)
	report := &pb.VantagePointReport{SchemaVersion: 1, DisclosureDelivery: &pb.DisclosureDeliveryObservation{Anchor: anchor, StoredThroughEpoch: 3, ScheduledToAckNs: int64(2 * time.Second), SampleAgeNs: int64(30 * time.Second)}}
	entry := &executorEntry{RegisteredExecutor: &RegisteredExecutor{TeslaAnchorKey: bytes.Clone(anchor), TeslaChainLength: 10}}
	entry.Capabilities = capabilitiesFromReport(&pb.ExecutorCapabilities{SchemaVersion: 1, Attribution: &pb.AttributionState{State: "available"}}, now)
	entry.capabilityObserved, entry.vantageObserved = now, now
	entry.vantage = vantageFromReport(report)
	observe := func(at time.Time) ExecutorResourceMetric {
		var metrics ExecutorHealthMetrics
		metrics.observe(entry, at, true)
		return metrics.DisclosureCompletion
	}
	if got := observe(now.Add(29 * time.Second)); got.Unknown != 0 || got.Value == nil || *got.Value != 2 {
		t.Fatal(got)
	}
	if got := observe(now.Add(30 * time.Second)); got.Unknown != 1 || got.Value != nil {
		t.Fatal("sample survived exact boundary", got)
	}
	// Input is copied before the caller can mutate it.
	report.DisclosureDelivery.Anchor[0] = 7
	if got := observe(now); got.Unknown != 0 {
		t.Fatal("report retained caller storage", got)
	}
	entry.TeslaAnchorKey = bytes.Repeat([]byte{9}, 32)
	if got := observe(now); got.Unknown != 1 {
		t.Fatal("other generation accepted", got)
	}
	entry.TeslaAnchorKey = anchor
	report.DisclosureDelivery.SampleAgeNs = -1
	if got := vantageFromReport(report); got.disclosureDelivery != nil {
		t.Fatal("negative age accepted")
	}
	report.DisclosureDelivery.SampleAgeNs = int64(time.Minute)
	if got := vantageFromReport(report); got.disclosureDelivery != nil {
		t.Fatal("expired age accepted")
	}
}
