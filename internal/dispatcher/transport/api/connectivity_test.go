// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// cpAdapter keeps optional reflection support alongside the production
// DispatcherState interface used by older scripted-peer tests.
func (a *cpAdapter) OnReflectAddress(ctx context.Context, mutation *rpc.Mutation, req *pb.ReflectAddressRequest, address string) (*pb.ReflectAddressResponse, error) {
	return a.d.OnReflectAddress(ctx, mutation, req, address)
}

func TestConnectivityFieldRefusalPrecedesUpload(t *testing.T) {
	f := ccNewFixture(t)
	c := f.client(f.root.URL, false)
	if _, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID, VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, Connectivity: &pb.ConnectivityReport{
		Ipv4: &pb.EgressTest{State: "unreachable", Reason: "reflector_failed"}, Ipv6: &pb.EgressTest{State: "untested", Reason: "not_configured"},
	}}}); err != nil {
		t.Fatal(err)
	}
	batch, err := client.Prepare([]client.Request{ccRequest(nil)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SubmitTEST(f.ctx, batch)
	var failure *client.HTTPError
	if !errors.As(err, &failure) || failure.Code != CodeInvalidPolicy || len(failure.FieldErrors) != 1 || failure.FieldErrors[0].Field != "policy.addresses" || failure.FieldErrors[0].Code != "reachability_failed" || failure.FieldErrors[0].OrderID == nil {
		t.Fatalf("missing structured refusal: %#v %v", failure, err)
	}
	if f.peer.uploadCount() != 0 {
		t.Fatal("refused capability reached runtime")
	}
	for _, listener := range []string{"tcp", "udp", "scion"} {
		t.Run(listener, func(t *testing.T) {
			request := ccRequest(nil)
			request.Policy.ListenTCP = listener == "tcp"
			request.Policy.ListenUDP = listener == "udp"
			request.Policy.ListenSCION = listener == "scion"
			batch, err := client.Prepare([]client.Request{request})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.SubmitTEST(f.ctx, batch)
			var failure *client.HTTPError
			if !errors.As(err, &failure) || failure.Code != CodeInvalidPolicy || len(failure.FieldErrors) != 1 || failure.FieldErrors[0].Field != "policy.listen_"+listener || failure.FieldErrors[0].Code != "unsupported" {
				t.Fatalf("missing structured listener refusal: %#v %v", failure, err)
			}
			if f.peer.uploadCount() != 0 {
				t.Fatal("unsupported listener reached runtime")
			}
		})
	}
}

func TestConnectivityResultUsesCapturedObservation(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, _, c := authAccount(t, f, "connectivity-owner")
	nonce := bytes.Repeat([]byte{8}, 32)
	if _, err := f.peer.direct.ReflectAddress(f.ctx, &pb.ReflectAddressRequest{ExecutorId: ccExecutorID, Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID, VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, Connectivity: &pb.ConnectivityReport{
		Ipv4: &pb.EgressTest{State: "reachable", Nonce: nonce}, Ipv6: &pb.EgressTest{State: "untested", Reason: "not_configured"},
	}}}); err != nil {
		t.Fatal(err)
	}
	nodes, err := c.Nodes(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Connectivity == nil || nodes[0].Connectivity.IPv4.State != "reachable" || nodes[0].Connectivity.IPv4.Address != "" {
		t.Fatalf("public discovery leaked address or lost observation: %+v", nodes)
	}
	id := f.submit(c, nil).IDs[0]
	document, err := c.Export(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if value := document.Provenance.VantagePoint.Connectivity; value == nil || value.IPv4.Address != "127.0.0.1" || value.IPv4.Source != wire.SourceDispatcherObserved {
		t.Fatalf("missing captured observation: %+v", value)
	}
	authGrantOperator(t, f, account.ID)
	nodes, err = c.Nodes(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Connectivity == nil || nodes[0].Connectivity.IPv4.Address != "127.0.0.1" {
		t.Fatalf("operator discovery lost captured address: %+v", nodes)
	}
	authRevokeOperator(t, f, account.ID)
	before, _ := json.Marshal(document.Provenance.VantagePoint)
	// Once the live registration disappears, exporting still reads the durable
	// admission record. It never reconstructs provenance from current discovery.
	f.d.OnExecutorDisconnected(f.peer.owner)
	document, err = c.Export(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(document.Provenance.VantagePoint)
	if !bytes.Equal(before, after) {
		t.Fatal("live registration changed portable provenance")
	}
	// Re-register the same identity with different live observations. Fetching
	// the result must keep using the original durable admission snapshot.
	replacement := apiTestOwner(t, f.d, ccExecutorID)
	host := "127.0.0.2"
	hello := &pb.HelloResponse{ExecutorId: ccExecutorID, PublicHost: &host, Version: "replacement", Currency: "TEST",
		VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, ScionIsdAs: "1-ff00:0:111", LocationOptOut: true,
			Connectivity: &pb.ConnectivityReport{Ipv4: &pb.EgressTest{State: "unreachable", Reason: "reflector_failed"}}}}
	if err := apiTestRegister(f.ctx, f.d, replacement, hello, "127.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if !replacement.MarkRegistered() {
		t.Fatal("replacement registration did not complete")
	}
	mutation := apiTestMutation(t, f.ctx, replacement)
	_, err = f.d.OnHeartbeat(f.ctx, mutation, &pb.HeartbeatRequest{ExecutorId: ccExecutorID, VantagePoint: hello.VantagePoint})
	mutation.Finish()
	if err != nil {
		t.Fatal(err)
	}
	nodes, err = c.Nodes(f.ctx)
	if err != nil || len(nodes) != 1 || nodes[0].Version != "replacement" || nodes[0].SCIONISDAS.Value == nil || *nodes[0].SCIONISDAS.Value != "1-ff00:0:111" || nodes[0].Connectivity == nil || nodes[0].Connectivity.IPv4.State != "unreachable" {
		t.Fatalf("replacement observations not visible: %+v %v", nodes, err)
	}
	document, err = c.Export(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	after, _ = json.Marshal(document.Provenance.VantagePoint)
	if !bytes.Equal(before, after) {
		t.Fatal("replacement registration rewrote the retained result snapshot")
	}
}
