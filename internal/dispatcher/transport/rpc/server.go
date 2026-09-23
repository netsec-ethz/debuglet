// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnsafeDispatcherServiceServer
	state DispatcherState
	bidi  *BidiServer
}

func (s *server) BindSession(ctx context.Context, in *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
	return s.bidi.confirm(ctx, in)
}
func (s *server) Heartbeat(ctx context.Context, in *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	ticket, err := s.bidi.admitted(ctx, in.GetExecutorId())
	if err != nil {
		return nil, err
	}
	defer ticket.Finish()
	if in.GetExecutorId() == "" {
		return nil, controlrpc.Denied()
	}
	return s.state.OnHeartbeat(ticket.Context(), ticket, in)
}
func (s *server) Resources(ctx context.Context, in *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
	ticket, err := s.bidi.admitted(ctx, in.GetExecutorId())
	if err != nil {
		return nil, err
	}
	defer ticket.Finish()
	if in.GetExecutorId() == "" {
		return nil, controlrpc.Denied()
	}
	return s.state.OnResources(ticket.Context(), ticket, in)
}
func (s *server) DebugletState(ctx context.Context, in *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
	ticket, err := s.bidi.admitted(ctx, in.GetExecutorId())
	if err != nil {
		return nil, err
	}
	defer ticket.Finish()
	if in.GetExecutorId() == "" {
		return nil, controlrpc.Denied()
	}
	return s.state.OnDebugletState(ticket.Context(), ticket, in)
}
func (s *server) DebugletAllocate(ctx context.Context, in *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
	ticket, err := s.bidi.admitted(ctx, in.GetExecutorId())
	if err != nil {
		return nil, err
	}
	defer ticket.Finish()
	if in.GetExecutorId() == "" {
		return nil, controlrpc.Denied()
	}
	return s.state.OnDebugletAllocate(ticket.Context(), ticket, in)
}
func (s *server) DebugletExit(ctx context.Context, in *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	ticket, err := s.bidi.admitted(ctx, "")
	if err != nil {
		return nil, err
	}
	defer ticket.Finish()
	return s.state.OnDebugletExit(ticket.Context(), ticket, in)
}
func (s *server) DebugletStream(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
	ticket, err := s.bidi.admitted(stream.Context(), "")
	if err != nil {
		return err
	}
	owner := ticket.Owner()
	// An idle receive must not hold a mutation. The callback validates the
	// first Ident frame and admits each later frame on this immutable owner.
	ticket.Finish()
	return s.state.OnDebugletStream(owner, stream)
}

// RenewLease is transport-owned: it reaches no application callback, and its
// ordinary mutation holds the reverse probe it makes.
func (s *server) RenewLease(ctx context.Context, in *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error) {
	return s.bidi.renewLease(ctx, in)
}
