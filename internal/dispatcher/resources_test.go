// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"math"
	"testing"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"
)

func resourceValue(n uint64) *pb.HostResourceValue { return &pb.HostResourceValue{Value: &n} }

func TestResourceReportValidationAndCopy(t *testing.T) {
	input := &pb.HostResources{ProcessRssBytes: resourceValue(0), OpenFds: resourceValue(7), StateAvailableBytes: resourceValue(10), StateCapacityBytes: resourceValue(100)}
	out := resourcesFromReport(input)
	*input.OpenFds.Value = 999
	if out.ProcessRSSBytes.Value == nil || *out.ProcessRSSBytes.Value != 0 || *out.OpenFDs.Value != 7 {
		t.Fatal("zero or immutable resource observation lost")
	}
	for _, tc := range []struct {
		name  string
		value *pb.HostResourceValue
		want  string
	}{
		{"omitted", nil, "missing"}, {"missing value", &pb.HostResourceValue{}, "invalid"},
		{"contradictory", &pb.HostResourceValue{Value: resourceValue(4).Value, Unavailable: "read"}, "invalid"},
		{"oversized", resourceValue(math.MaxUint64), "invalid"},
		{"untrusted reason", &pb.HostResourceValue{Unavailable: "/private/path"}, "invalid"},
		{"permission", &pb.HostResourceValue{Unavailable: "permission"}, "permission"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resourcesFromReport(&pb.HostResources{ProcessRssBytes: tc.value, OpenFds: resourceValue(65537)})
			if got.ProcessRSSBytes.Value != nil || got.ProcessRSSBytes.Unavailable != tc.want || got.OpenFDs.Value != nil {
				t.Fatalf("invalid field accepted: %+v", got)
			}
		})
	}
	for _, capacity := range []uint64{0, 9} {
		input.StateCapacityBytes = resourceValue(capacity)
		got := resourcesFromReport(input)
		if got.StateAvailableBytes.Value != nil || got.StateCapacityBytes.Value != nil || got.ProcessRSSBytes.Value == nil {
			t.Fatal("inconsistent filesystem report affected unrelated fields or remained numeric")
		}
	}
}

func TestResourceAndAttachmentObservationsExpireAndRecover(t *testing.T) {
	now := time.Unix(10000, 0)
	e := &executorEntry{RegisteredExecutor: &RegisteredExecutor{}}
	e.Capabilities = capabilitiesFromReport(&pb.ExecutorCapabilities{SchemaVersion: 1, EnforcementMode: "ebpf"}, now)
	e.capabilityObserved, e.vantageObserved = now, now
	set := func(state string, rss, fds, available, capacity uint64) {
		e.vantage = vantageFromReport(&pb.VantagePointReport{SchemaVersion: 1, CounterAttachment: state,
			Resources: &pb.HostResources{ProcessRssBytes: resourceValue(rss), OpenFds: resourceValue(fds), StateAvailableBytes: resourceValue(available), StateCapacityBytes: resourceValue(capacity)}})
	}
	set("present", 100, 5, 90, 100)
	var h ExecutorHealthMetrics
	h.observe(e, now, true)
	set("missing", 50, 9, 4, 200)
	h.observe(e, now, true)
	if h.AttachmentPresent != 1 || h.AttachmentMissing != 1 || *h.RSS.Value != 100 || *h.FDs.Value != 9 || *h.StateAvailable.Value != 4 || *h.StateAvailableRatio.Value != .02 {
		t.Fatalf("wrong extrema or missing attachment: %+v", h)
	}
	for _, tc := range []struct {
		name      string
		age       time.Duration
		connected bool
	}{
		{"expired", capabilityLifetime, true}, {"future", -time.Second, true}, {"disconnected", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.capabilityObserved, e.vantageObserved = now.Add(-tc.age), now.Add(-tc.age)
			h = ExecutorHealthMetrics{}
			h.observe(e, now, tc.connected)
			if h.AttachmentUnknown != 1 || h.AttachmentPresent != 0 || h.RSS.Unknown != 1 || h.RSS.Value != nil || h.StateAvailableRatio.Unknown != 1 {
				t.Fatalf("unavailable report remained positive: %+v", h)
			}
		})
	}
	e.capabilityObserved, e.vantageObserved = now, now
	for _, state := range []string{"", "arbitrary"} {
		set(state, 100, 5, 90, 100)
		h = ExecutorHealthMetrics{}
		h.observe(e, now, true)
		if h.AttachmentUnknown != 1 {
			t.Fatal("omitted or unknown attachment established recovery")
		}
	}
	set("present", 100, 5, 90, 100)
	h = ExecutorHealthMetrics{}
	h.observe(e, now, true)
	if h.AttachmentPresent != 1 || h.RSS.Unknown != 0 {
		t.Fatal("fresh report did not recover")
	}
	e.Capabilities.EnforcementMode = "fallback"
	h = ExecutorHealthMetrics{}
	h.observe(e, now, true)
	if h.AttachmentNotRequired != 1 || h.AttachmentPresent != 0 {
		t.Fatal("fallback claimed an eBPF attachment")
	}
}
