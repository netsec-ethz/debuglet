package rpc

import (
	"context"
	pb "debuglet/protocol"
)

type server struct {
	pb.UnsafeExecutorServiceServer
	state ExecutorState
}

func (s *server) Hello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	return s.state.OnHello(ctx, in)
}
func (s *server) Upload(ctx context.Context, in *pb.UploadRequest) (*pb.UploadResponse, error) {
	return s.state.OnUpload(ctx, in)
}
func (s *server) Abort(ctx context.Context, in *pb.AbortRequest) (*pb.AbortResponse, error) {
	return s.state.OnAbort(ctx, in)
}
func (s *server) Bandwidth(ctx context.Context, in *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	return s.state.OnBandwidth(ctx, in)
}
