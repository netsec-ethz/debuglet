// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestCapabilitiesCrossBoundControlHTTPAndSDK(t *testing.T) {
	f := ccNewFixture(t)
	c := f.client(f.root.URL, false)
	filter := client.ExecutorFilter{Protocols: []string{"icmp"}, EnforcementMode: "fallback"}
	if _, err := c.SelectExecutor(f.ctx, "", filter); err == nil {
		t.Fatal("legacy peer matched unknown capabilities")
	}
	_, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID,
		Capabilities: &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp", "icmp"}, EnforcementMode: "fallback"}})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := c.SelectExecutor(f.ctx, "", filter)
	if err != nil || selected.ID != ccExecutorID || selected.Capabilities == nil || selected.Capabilities.AdvertisedCapacityBPS == nil || *selected.Capabilities.AdvertisedCapacityBPS != int64(ccCapacity) {
		t.Fatalf("bound control report did not reach HTTP/SDK discovery: %+v %v", selected, err)
	}
	if selected.Capabilities.Attribution != nil {
		t.Fatal("report without attribution state claimed one")
	}
	rec := httptest.NewRecorder()
	f.root.Config.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/executors", nil).WithContext(f.ctx))
	oaCheckResponse(t, oaContract(t), http.MethodGet, "/executors", rec.Code, rec.Body.Bytes())
	installed, age, held := int64(6), int64(3000), int64(15000)
	_, err = f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID,
		Capabilities: &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp", "icmp"}, EnforcementMode: "fallback",
			Attribution: &pb.AttributionState{State: "unavailable", Reason: "refresh_failing", Epoch: 7, InstalledEpoch: &installed,
				LastRefreshAgeMs: &age, RefreshError: "stale key remains installed", DisclosureHeldMs: &held}}})
	if err != nil {
		t.Fatal(err)
	}
	selected, err = c.SelectExecutor(f.ctx, "", filter)
	if err != nil || selected.Capabilities.Attribution == nil || selected.Capabilities.Attribution.Reason != "refresh_failing" ||
		*selected.Capabilities.Attribution.InstalledEpoch != installed || selected.Capabilities.Attribution.DisclosureHeldSince == nil {
		t.Fatalf("attribution state did not reach HTTP/SDK discovery: %+v %v", selected.Capabilities, err)
	}
	rec = httptest.NewRecorder()
	f.root.Config.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/executors", nil).WithContext(f.ctx))
	oaCheckResponse(t, oaContract(t), http.MethodGet, "/executors", rec.Code, rec.Body.Bytes())
	observed := selected.Capabilities.ObservedAt
	if _, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID}); err != nil {
		t.Fatal(err)
	}
	selected, err = c.SelectExecutor(f.ctx, "", filter)
	if err != nil || selected.Capabilities.ObservedAt != observed {
		t.Fatal("nil heartbeat report changed observation")
	}
	if _, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID, Capabilities: &pb.ExecutorCapabilities{SchemaVersion: 99}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelectExecutor(f.ctx, "", filter); err == nil {
		t.Fatal("unknown control report retained positive discovery")
	}
	f.peer.owner.Retire()
	if _, err := c.SelectExecutor(f.ctx, "", client.ExecutorFilter{}); err == nil {
		t.Fatal("retired control binding remained selectable")
	}
}
