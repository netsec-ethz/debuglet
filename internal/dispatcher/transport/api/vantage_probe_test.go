// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// ICMP, fallback reason and clock reach the public listing; the host platform
// reaches only the owner-or-operator result, never GET /executors.
func TestProbeResultsCrossHTTPAndStayPrivate(t *testing.T) {
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}
	f := ccNewFixtureConfigured(t, zap.NewNop(), peer, func(*dispatcher.Dispatcher) error { return nil }, LocalDevelopment(true))
	c := f.client(f.root.URL, false)
	estimated, maximum, memory := int64(3e6), int64(50e6), uint64(4<<30)
	if _, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID,
		Capabilities: &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, EnforcementMode: "fallback", EnforcementReason: "not_permitted",
			Icmp: &pb.ProbeState{State: "unavailable", Reason: "not_permitted"}},
		VantagePoint: &pb.VantagePointReport{SchemaVersion: 1,
			Clock:    &pb.ClockState{State: "synced", EstimatedErrorNs: &estimated, MaxErrorNs: &maximum, ErrorBoundNs: 100e6, Readiness: "ready"},
			Platform: &pb.HostPlatform{Os: "linux", Arch: "arm64", KernelRelease: "6.1.0-private", Cpus: 4, MemoryBytes: &memory, BuildVersion: "0.3.0"}}}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.root.Config.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/executors", nil).WithContext(f.ctx))
	oaCheckResponse(t, oaContract(t), http.MethodGet, "/executors", rec.Code, rec.Body.Bytes())
	if body := rec.Body.String(); strings.Contains(body, "6.1.0-private") || strings.Contains(body, "kernel_release") || strings.Contains(body, "platform") {
		t.Fatalf("platform detail in the public listing: %s", body)
	}
	var nodes []wire.Executor
	if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil || len(nodes) != 1 {
		t.Fatalf("executors: %s %v", rec.Body.String(), err)
	}
	node := nodes[0]
	if cl := node.Clock; cl.Value == nil || cl.Value.State != "synced" || *cl.Value.EstimatedErrorNS != estimated || *cl.Source != wire.SourceExecutorReported {
		t.Fatalf("clock: %+v", cl)
	}
	if cap := node.Capabilities; cap == nil || cap.EnforcementReason != "not_permitted" || cap.ICMP == nil || cap.ICMP.Reason != "not_permitted" {
		t.Fatalf("capabilities: %+v", cap)
	}

	doc, err := c.Export(f.ctx, f.submit(c, nil).IDs[0])
	if err != nil {
		t.Fatal(err)
	}
	v := doc.Provenance.VantagePoint
	if p := v.Platform; p.Value == nil || *p.Value.KernelRelease != "6.1.0-private" || *p.Value.CPUs != 4 || *p.Source != wire.SourceExecutorReported || *p.Stale {
		t.Fatalf("admitted platform: %+v", p)
	}
	if cl := v.Clock; cl.Value == nil || cl.Value.Readiness != "ready" || *cl.Source != wire.SourceExecutorReported {
		t.Fatalf("admitted clock: %+v", cl)
	}
	if cap := v.Capabilities.Value; cap == nil || cap.EnforcementReason != "not_permitted" || cap.ICMP == nil || cap.ICMP.State != "unavailable" {
		t.Fatalf("admitted capabilities: %+v", cap)
	}
	// The kernel clock estimate is not a bound on the run's timestamps.
	if doc.Timing.ClockUncertaintyNS != nil {
		t.Fatal("clock uncertainty invented")
	}
}
