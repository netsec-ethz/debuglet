// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// Admission records a stale report as stale rather than dropping it, labels a
// hello-supplied source IP as the executor's claim, and leaves absent facts null.
func TestAdmissionVantagePointLabels(t *testing.T) {
	observed := time.Unix(1700000000, 0)
	host := "vantage.example"
	entry := &executorEntry{RegisteredExecutor: &RegisteredExecutor{
		Capabilities:       &wire.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, EnforcementMode: "fallback"},
		capabilityObserved: observed, sourceIp: "192.0.2.9", publicHost: &host,
	}}
	v := admissionVantagePoint(entry, observed.Add(capabilityLifetime))
	if got := v.Capabilities; got.Value == nil || !*got.Stale || !got.ObservedAt.Equal(observed) || *got.Source != wire.SourceExecutorReported {
		t.Fatalf("stale report: %+v", got)
	}
	if *v.SourceIP.Source != wire.SourceExecutorReported || *v.PublicHost.Value != host || *v.PublicHost.Source != wire.SourceExecutorReported {
		t.Fatalf("labels: %+v", v)
	}
	entry.Capabilities.Protocols[0] = "changed"
	if v.Capabilities.Value.Protocols[0] != "tcp" {
		t.Fatal("snapshot aliases the registry")
	}
	if fresh := admissionVantagePoint(entry, observed.Add(time.Second)); *fresh.Capabilities.Stale {
		t.Fatal("fresh report marked stale")
	}
	entry.sourceIPObserved = true
	if v := admissionVantagePoint(entry, observed); *v.SourceIP.Source != wire.SourceDispatcherObserved {
		t.Fatalf("observed ip: %+v", v.SourceIP)
	}
	empty := admissionVantagePoint(&executorEntry{RegisteredExecutor: &RegisteredExecutor{}}, observed)
	if empty.SchemaVersion != 1 || empty.Capabilities != (wire.VantageCapabilities{}) || empty.SourceIP != (wire.LabelledString{}) || empty.PublicHost != (wire.LabelledString{}) {
		t.Fatalf("invented facts: %+v", empty)
	}
}

func TestCapabilitySnapshotsExpireAndFollowBinding(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	now := time.Unix(1700000000, 0)
	d.now = func() time.Time { return now }
	owner := registryOwner(t, "capability")
	hello := registryHello("capability")
	hello.Capabilities = &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp", "icmp"}, EnforcementMode: "fallback"}
	if err := registryRegisterWithSetup(t.Context(), d, owner, hello, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	owner.MarkRegistered()
	get := func() *RegisteredExecutor {
		t.Helper()
		snapshot, ok := d.GetExecutor("capability")
		if !ok {
			t.Fatal("current registration missing")
		}
		return snapshot
	}
	snapshot := get()
	if snapshot.Capabilities == nil || snapshot.Capabilities.AdvertisedCapacityBPS != nil {
		t.Fatal("missing report or invented pre-resource capacity")
	}
	hello.Capabilities.Protocols[0] = "changed"
	snapshot.Capabilities.Protocols[0] = "changed-output"
	if get().Capabilities.Protocols[0] != "tcp" {
		t.Fatal("capability snapshot aliases a caller")
	}
	d.mu.Lock()
	d.executors["capability"].capacity = 123
	d.mu.Unlock()
	if got := get().Capabilities.AdvertisedCapacityBPS; got == nil || *got != 123 {
		t.Fatal("advertised capacity missing")
	}
	heartbeat := func(report *pb.ExecutorCapabilities) {
		t.Helper()
		mutation := effectTestMutation(t, d, "capability")
		_, err := d.OnHeartbeat(t.Context(), mutation, &pb.HeartbeatRequest{ExecutorId: "capability", Capabilities: report})
		mutation.Finish()
		if err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(30 * time.Second)
	heartbeat(nil)
	if get().Capabilities.ObservedAt != snapshot.Capabilities.ObservedAt {
		t.Fatal("absent heartbeat report renewed cached observation")
	}
	now = now.Add(capabilityLifetime - 30*time.Second)
	if get().Capabilities != nil {
		t.Fatal("old capability snapshot stayed selectable")
	}
	// A nil update is no new observation. An unsupported nonnil update clears
	// capabilities; it cannot inherit a previous positive declaration.
	if capabilitiesFromReport(nil, now) != nil || capabilitiesFromReport(&pb.ExecutorCapabilities{SchemaVersion: 2}, now) != nil {
		t.Fatal("unknown report accepted")
	}
	for _, report := range []*pb.ExecutorCapabilities{
		{SchemaVersion: 1, Protocols: []string{"tcp", "tcp"}},
		{SchemaVersion: 1, Protocols: []string{"made-up"}},
		{SchemaVersion: 1, EnforcementMode: "auto"},
	} {
		if capabilitiesFromReport(report, now) != nil {
			t.Fatal("malformed report accepted")
		}
	}
	heartbeat(&pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"udp"}})
	if get().Capabilities == nil {
		t.Fatal("new observation did not restore discovery")
	}
	heartbeat(&pb.ExecutorCapabilities{SchemaVersion: 99})
	if get().Capabilities != nil {
		t.Fatal("unsupported heartbeat report retained positive capabilities")
	}
	owner.Retire()
	replacement := registryOwner(t, "capability")
	if err := registryRegisterWithSetup(context.Background(), d, replacement, registryHello("capability"), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	replacement.MarkRegistered()
	d.OnExecutorDisconnected(owner)
	if get().Capabilities != nil {
		t.Fatal("replacement inherited old capabilities")
	}
	replacement.Retire()
	if _, ok := d.GetExecutor("capability"); ok {
		t.Fatal("retired binding visible")
	}
}
