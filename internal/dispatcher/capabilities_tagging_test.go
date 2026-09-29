// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// A valid tagging mode is carried as reported; a report without one keeps
// tagging unknown; a malformed one leaves tagging unknown too and keeps the
// rest of the report, as for attribution.
func TestCapabilityTaggingValidation(t *testing.T) {
	observed := time.Unix(1700000000, 0)
	report := func(m *pb.TaggingMode) *pb.ExecutorCapabilities {
		return &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp", "scion"}, EnforcementMode: "ebpf", Tagging: m}
	}
	if got := capabilitiesFromReport(report(nil), observed); got == nil || got.Tagging != nil {
		t.Fatalf("older executor: %+v", got)
	}
	for _, valid := range []*pb.TaggingMode{
		{Ipv4: "ebpf", Ipv6: "none", Scion: "none"},
		{Ipv4: "userspace", Ipv6: "none", Scion: "none"},
		{Ipv4: "none", Ipv6: "none", Scion: "none"},
	} {
		got := capabilitiesFromReport(report(valid), observed)
		if got == nil || got.Tagging == nil || *got.Tagging != (wire.TaggingMode{IPv4: valid.Ipv4, IPv6: valid.Ipv6, SCION: valid.Scion}) {
			t.Errorf("valid %v: %+v", valid, got)
		}
	}
	for spec, want := range map[string]string{
		"debuglet-tag-v1":       "debuglet-tag-v1",
		"debuglet-tag-v2":       "debuglet-tag-v2",
		"":                      "",
		"Debuglet-Tag-V1":       "",
		"v1; drop table":        "",
		strings.Repeat("a", 65): "",
	} {
		got := capabilitiesFromReport(report(&pb.TaggingMode{Ipv4: "ebpf", Ipv6: "none", Scion: "none", TagSpec: spec}), observed)
		if got == nil || got.Tagging == nil || got.Tagging.TagSpec != want || got.Tagging.IPv4 != "ebpf" {
			t.Errorf("tag spec %q: %+v, want %q with the modes kept", spec, got.Tagging, want)
		}
	}
	for name, invalid := range map[string]*pb.TaggingMode{
		"empty":         {},
		"missing ipv6":  {Ipv4: "ebpf", Scion: "none"},
		"unknown ipv4":  {Ipv4: "fallback", Ipv6: "none", Scion: "none"},
		"unknown scion": {Ipv4: "ebpf", Ipv6: "none", Scion: "path"},
		"case":          {Ipv4: "EBPF", Ipv6: "none", Scion: "none"},
	} {
		got := capabilitiesFromReport(report(invalid), observed)
		if got == nil || got.Tagging != nil || !slices.Equal(got.Protocols, []string{"tcp", "scion"}) || got.EnforcementMode != "ebpf" {
			t.Errorf("%s: %+v, want the report without tagging", name, got)
		}
	}
}

// The discovery snapshot and the admission record both carry the tagging mode
// without aliasing the registry, and the result's vantage point writes it as
// an additive field.
func TestCapabilityTaggingSnapshots(t *testing.T) {
	observed := time.Unix(1700000000, 0)
	entry := &executorEntry{RegisteredExecutor: &RegisteredExecutor{
		Capabilities: capabilitiesFromReport(&pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, EnforcementMode: "ebpf",
			Tagging: &pb.TaggingMode{Ipv4: "ebpf", Ipv6: "none", Scion: "none", TagSpec: wire.TagSpecV1}}, observed),
		capabilityObserved: observed,
	}}
	want := wire.TaggingMode{IPv4: "ebpf", IPv6: "none", SCION: "none", TagSpec: wire.TagSpecV1}
	snapshot := capabilitySnapshot(entry, observed.Add(time.Second))
	admitted := admissionVantagePoint(entry, observed.Add(time.Second))
	if snapshot == nil || snapshot.Tagging == nil || *snapshot.Tagging != want {
		t.Fatalf("discovery snapshot: %+v", snapshot)
	}
	if admitted.Capabilities.Value == nil || admitted.Capabilities.Value.Tagging == nil || *admitted.Capabilities.Value.Tagging != want {
		t.Fatalf("admission snapshot: %+v", admitted.Capabilities.Value)
	}
	entry.Capabilities.Tagging.IPv4 = "none"
	if snapshot.Tagging.IPv4 != "ebpf" || admitted.Capabilities.Value.Tagging.IPv4 != "ebpf" {
		t.Fatal("snapshot aliases the registry tagging")
	}
	document, err := json.Marshal(admitted)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), `"tagging":{"ipv4":"ebpf","ipv6":"none","scion":"none","tag_spec":"debuglet-tag-v1"}`) {
		t.Fatalf("vantage point document: %s", document)
	}

	entry.Capabilities.Tagging = nil
	document, err = json.Marshal(admissionVantagePoint(entry, observed))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), `"tagging":null`) {
		t.Fatalf("unknown tagging is not null: %s", document)
	}
}
