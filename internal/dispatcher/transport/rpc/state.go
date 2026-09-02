package rpc

import (
	"context"
	pb "debuglet/protocol"

	"google.golang.org/grpc"
)

type DispatcherState interface {
	OnHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error)
	OnResources(ctx context.Context, req *pb.ResourcesRequest) (*pb.ResourcesResponse, error)
	OnDebugletState(ctx context.Context, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error)
	OnDebugletAllocate(ctx context.Context, req *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error)
	OnDebugletExit(ctx context.Context, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error)

	OnDebugletStream(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error

	// OnExecutorConnected is called once the Hello handshake completes.
	// sourceIP is the executor's address as observed on the control
	// connection — the address its probe traffic will appear to come
	// from, and the key used by GET /executors/by-ip.
	OnExecutorConnected(hello *pb.HelloResponse, sourceIP string)
	OnExecutorDisconnected(execID string)
}
