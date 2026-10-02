// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type metadataDaemon struct {
	capabilityDaemon
	expired atomic.Bool
	target  atomic.Uint64
}

func (d *metadataDaemon) Paths(_ context.Context, req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {
	d.target.Store(req.DestinationIsdAs)
	expires := time.Now().Add(time.Minute)
	if d.expired.Load() {
		expires = time.Now().Add(-time.Minute)
	}
	return &sdpb.PathsResponse{Paths: []*sdpb.Path{{Expiration: timestamppb.New(expires), Mtu: 1500,
		Interface:  &sdpb.Interface{Address: &sdpb.Underlay{Address: "127.0.0.1:30254"}},
		Interfaces: []*sdpb.PathInterface{{IsdAs: req.SourceIsdAs, Id: 1}, {IsdAs: req.DestinationIsdAs, Id: 2}}}}}, nil
}

func TestSCIONHostAndControlledRemotePathMetadata(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	daemon := &metadataDaemon{}
	server := grpc.NewServer()
	sdpb.RegisterDaemonServiceServer(server, daemon)
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	defer func() { server.Stop(); <-done }()
	t.Setenv("SCION_DAEMON_ADDRESS", listener.Addr().String())
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ia, host, paths := scionDetails(ctx, "1-ff00:0:111")
	if ia.String() != "1-ff00:0:110" || host != "127.0.0.1" || paths.GetState() != "available" || daemon.target.Load() != uint64(addr.MustIAFrom(1, 0xff00_0000_0111)) {
		t.Fatalf("SCION observation: %v %q %v", ia, host, paths)
	}
	daemon.expired.Store(true)
	_, _, paths = scionDetails(ctx, "1-ff00:0:111")
	if paths.GetState() != "unavailable" || paths.GetReason() != "no_path" {
		t.Fatalf("expired path remained available: %v", paths)
	}
	_, _, paths = scionDetails(ctx, "")
	if paths != nil {
		t.Fatal("unconfigured remote path was measured")
	}
}
