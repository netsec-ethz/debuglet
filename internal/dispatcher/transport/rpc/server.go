package rpc

import (
	"context"
	pb "debuglet/protocol"

	"google.golang.org/grpc"
)

type server struct {
	pb.UnsafeDispatcherServiceServer
	state DispatcherState
}

func (s *server) Heartbeat(ctx context.Context, in *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	return s.state.OnHeartbeat(ctx, in)
}
func (s *server) Resources(ctx context.Context, in *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
	return s.state.OnResources(ctx, in)
}
func (s *server) DebugletState(ctx context.Context, in *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
	return s.state.OnDebugletState(ctx, in)
}
func (s *server) DebugletAllocate(ctx context.Context, in *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
	return s.state.OnDebugletAllocate(ctx, in)
}
func (s *server) DebugletExit(ctx context.Context, in *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	return s.state.OnDebugletExit(ctx, in)
}
func (s *server) DebugletStream(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
	return s.state.OnDebugletStream(stream)
}
