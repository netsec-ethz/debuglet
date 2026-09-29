// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestDiscoveryRequiresPositiveFreshServerObservations(t *testing.T) {
	capacity := int64(100)
	nodes := []Node{
		{ID: "legacy", Ready: true},
		{ID: "plain", Ready: true, Capabilities: &wire.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, EnforcementMode: "fallback", AdvertisedCapacityBPS: &capacity}},
		{ID: "scion", Ready: true, Capabilities: &wire.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp", "scion", "icmp"}, EnforcementMode: "ebpf", AdvertisedCapacityBPS: &capacity}},
		{ID: "stale", Ready: false, Capabilities: &wire.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"scion"}}},
		{ID: "future", Ready: true, Capabilities: &wire.ExecutorCapabilities{SchemaVersion: 2, Protocols: []string{"scion"}}},
	}
	f := newFakeServer(t, "")
	f.handle("GET /executors", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(nodes) })
	c := f.client(t, Options{})
	minimum := int64(100)
	selected, err := c.SelectExecutor(t.Context(), "", ExecutorFilter{Protocols: []string{"scion", "icmp"}, EnforcementMode: "ebpf", MinCapacityBPS: &minimum})
	if err != nil || selected.ID != "scion" {
		t.Fatalf("heterogeneous selection: %v %v", selected, err)
	}
	if _, err := c.SelectExecutor(t.Context(), "", ExecutorFilter{}); err == nil {
		t.Fatal("ambiguous ready executors silently selected")
	}
	if _, err := c.SelectExecutor(t.Context(), "legacy", ExecutorFilter{Protocols: []string{"tcp"}}); err == nil {
		t.Fatal("explicit ID bypassed requested capabilities")
	}
	minimum = 101
	if _, err := c.SelectExecutor(t.Context(), "", ExecutorFilter{MinCapacityBPS: &minimum}); err == nil {
		t.Fatal("insufficient capacity matched")
	}
	nodes[2].Capabilities = nil // Fresh dispatcher answer expired/replaced the observation.
	if _, err := c.SelectExecutor(t.Context(), "", ExecutorFilter{Protocols: []string{"scion"}}); err == nil {
		t.Fatal("cached capabilities survived a fresh unknown snapshot")
	}
	before := len(f.requests())
	if _, err := c.DiscoverExecutors(t.Context(), ExecutorFilter{Protocols: []string{"typo"}}); err == nil || len(f.requests()) != before {
		t.Fatal("invalid filter reached the server")
	}
}

func TestDiscoveryFiltersByReportedISDAS(t *testing.T) {
	ia := func(s string) wire.ObservedString { return wire.ObservedString{Value: &s} }
	nodes := []Node{
		{ID: "unknown", Ready: true},
		{ID: "other", Ready: true, SCIONISDAS: ia("1-ff00:0:111")},
		{ID: "match", Ready: true, SCIONISDAS: ia("1-ff00:0:110"), Capabilities: &wire.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"scion"}}},
		{ID: "offline", Ready: false, SCIONISDAS: ia("1-ff00:0:110")},
	}
	f := newFakeServer(t, "")
	f.handle("GET /executors", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(nodes) })
	c := f.client(t, Options{})
	// An equivalent spelling selects the same executor, alone or combined
	// with a capability filter.
	for _, filter := range []ExecutorFilter{{ISDAS: "1-ff00:0:0110"}, {ISDAS: "1-ff00:0:110", Protocols: []string{"scion"}}} {
		if selected, err := c.SelectExecutor(t.Context(), "", filter); err != nil || selected.ID != "match" {
			t.Fatalf("%+v: %v %v", filter, selected, err)
		}
	}
	if _, err := c.SelectExecutor(t.Context(), "", ExecutorFilter{ISDAS: "1-ff00:0:110", Protocols: []string{"icmp"}}); err == nil {
		t.Fatal("ISD-AS bypassed a capability filter")
	}
	if matched, err := c.DiscoverExecutors(t.Context(), ExecutorFilter{ISDAS: "2-1"}); err != nil || len(matched) != 0 {
		t.Fatalf("unknown ISD-AS matched: %v %v", matched, err)
	}
	before := len(f.requests())
	for _, bad := range []string{"1-0", "ff00:0:110", "1-ff00:0:110 "} {
		if _, err := c.DiscoverExecutors(t.Context(), ExecutorFilter{ISDAS: bad}); err == nil || len(f.requests()) != before {
			t.Fatalf("invalid ISD-AS filter %q reached the server", bad)
		}
	}
}
