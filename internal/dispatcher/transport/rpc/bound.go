package rpc

import (
	"context"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

// BoundExecutorClient is permanently bound to one negotiated callback session.
// Hello belongs to setup and is deliberately absent here. An RPC that returns
// does not prove that its remote handler has stopped.
type BoundExecutorClient interface {
	Upload(context.Context, *pb.UploadRequest, ...grpc.CallOption) (*pb.UploadResponse, error)
	Abort(context.Context, *pb.AbortRequest, ...grpc.CallOption) (*pb.AbortResponse, error)
	Bandwidth(context.Context, *pb.BandwidthRequest, ...grpc.CallOption) (*pb.BandwidthResponse, error)
}
