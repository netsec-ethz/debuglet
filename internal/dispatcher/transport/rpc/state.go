// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"google.golang.org/grpc"
)

// DispatcherState is the application behind this transport. A unary callback is
// handed the mutation it was admitted under and must fork it for any local work
// that outlives the call. A stream is handed its owner instead and admits each
// frame separately.
type DispatcherState interface {
	OnHeartbeat(ctx context.Context, mutation *Mutation, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error)
	OnResources(ctx context.Context, mutation *Mutation, req *pb.ResourcesRequest) (*pb.ResourcesResponse, error)
	OnDebugletState(ctx context.Context, mutation *Mutation, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error)
	OnDebugletAllocate(ctx context.Context, mutation *Mutation, req *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error)
	OnDebugletExit(ctx context.Context, mutation *Mutation, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error)

	OnDebugletStream(owner *SessionOwner, stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error

	// OnExecutorConnected is called once an owner has been published for this
	// session, under the setup mutation the transport admitted for it: that
	// context is canceled on retirement or shutdown, the transport finishes
	// the mutation, and the callback therefore admits none of its own and must
	// return before a replacement session may proceed. Registration is marked
	// only after it returns successfully.
	// sourceIP is the executor's address as observed on the control
	// connection — the address its probe traffic will appear to come
	// from, and the key used by GET /executors/by-ip.
	OnExecutorConnected(ctx context.Context, owner *SessionOwner, hello *pb.HelloResponse, sourceIP string) error
	OnExecutorDisconnected(owner *SessionOwner)
}
