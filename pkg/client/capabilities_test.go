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
