package rpc

import (
	"context"
	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Each returned client carries one immutable binding and rechecks its lease
// before every call, so no request is retargeted at a later session.
type boundDispatcherClient struct {
	client      pb.DispatcherServiceClient
	credentials controlrpc.Credentials
	owner       *BidiClient
}

func (c *boundDispatcherClient) Heartbeat(ctx context.Context, in *pb.HeartbeatRequest, opts ...grpc.CallOption) (*pb.HeartbeatResponse, error) {
	if err := c.owner.CheckLease(c.credentials.Binding); err != nil {
		return nil, err
	}
	out, err := c.client.Heartbeat(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
func (c *boundDispatcherClient) Resources(ctx context.Context, in *pb.ResourcesRequest, opts ...grpc.CallOption) (*pb.ResourcesResponse, error) {
	if err := c.owner.CheckLease(c.credentials.Binding); err != nil {
		return nil, err
	}
	out, err := c.client.Resources(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
func (c *boundDispatcherClient) DebugletState(ctx context.Context, in *pb.DebugletStateRequest, opts ...grpc.CallOption) (*pb.DebugletStateResponse, error) {
	if err := c.owner.CheckLease(c.credentials.Binding); err != nil {
		return nil, err
	}
	out, err := c.client.DebugletState(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
func (c *boundDispatcherClient) DebugletAllocate(ctx context.Context, in *pb.DebugletAllocateRequest, opts ...grpc.CallOption) (*pb.DebugletAllocateResponse, error) {
	if err := c.owner.CheckLease(c.credentials.Binding); err != nil {
		return nil, err
	}
	out, err := c.client.DebugletAllocate(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
func (c *boundDispatcherClient) DebugletExit(ctx context.Context, in *pb.DebugletExitRequest, opts ...grpc.CallOption) (*pb.DebugletExitResponse, error) {
	if err := c.owner.CheckLease(c.credentials.Binding); err != nil {
		return nil, err
	}
	out, err := c.client.DebugletExit(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
func (c *boundDispatcherClient) BindSession(ctx context.Context, in *pb.BindSessionRequest, opts ...grpc.CallOption) (*pb.BindSessionResponse, error) {
	return nil, controlrpc.Unavailable()
}
func (c *boundDispatcherClient) RenewLease(ctx context.Context, in *pb.RenewLeaseRequest, opts ...grpc.CallOption) (*pb.RenewLeaseResponse, error) {
	return nil, controlrpc.Unavailable() // The sole transport-owned renewal loop owns sequence/deadline.
}
func (c *boundDispatcherClient) DebugletStream(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[pb.DebugletStreamRequest, pb.DebugletStreamResponse], error) {
	if err := c.owner.CheckLease(c.credentials.Binding); err != nil {
		return nil, err
	}
	stream, err := c.client.DebugletStream(c.credentials.Outgoing(ctx), opts...)
	if err != nil {
		return nil, c.credentials.RedactError(err)
	}
	return &boundDispatcherStream{BidiStreamingClient: stream, credentials: c.credentials, owner: c.owner}, nil
}

// gRPC can deliver a peer status on any stream operation, including after a
// successful opening, so a caller keeps one owner for sending and receiving.
type boundDispatcherStream struct {
	grpc.BidiStreamingClient[pb.DebugletStreamRequest, pb.DebugletStreamResponse]
	credentials controlrpc.Credentials
	owner       *BidiClient
}

func (s *boundDispatcherStream) Send(in *pb.DebugletStreamRequest) error {
	if err := s.owner.CheckLease(s.credentials.Binding); err != nil {
		return err
	}
	return s.credentials.RedactError(s.BidiStreamingClient.Send(in))
}
func (s *boundDispatcherStream) Recv() (*pb.DebugletStreamResponse, error) {
	out, err := s.BidiStreamingClient.Recv()
	return out, s.credentials.RedactError(err)
}
func (s *boundDispatcherStream) Header() (metadata.MD, error) {
	out, err := s.BidiStreamingClient.Header()
	return out, s.credentials.RedactError(err)
}
func (s *boundDispatcherStream) CloseSend() error {
	return s.credentials.RedactError(s.BidiStreamingClient.CloseSend())
}
func (s *boundDispatcherStream) SendMsg(in any) error {
	if err := s.owner.CheckLease(s.credentials.Binding); err != nil {
		return err
	}
	return s.credentials.RedactError(s.BidiStreamingClient.SendMsg(in))
}
func (s *boundDispatcherStream) RecvMsg(out any) error {
	return s.credentials.RedactError(s.BidiStreamingClient.RecvMsg(out))
}
