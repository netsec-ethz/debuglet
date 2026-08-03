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

	OnExecutorConnected(hello *pb.HelloResponse)
	OnExecutorDisconnected(execID string)
}
