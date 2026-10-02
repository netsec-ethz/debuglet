// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"net"
	"net/netip"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func (s *server) ReflectAddress(ctx context.Context, in *pb.ReflectAddressRequest) (*pb.ReflectAddressResponse, error) {
	ticket, err := s.bidi.admitted(ctx, in.GetExecutorId())
	if err != nil {
		return nil, err
	}
	defer ticket.Finish()
	if in.GetExecutorId() == "" || len(in.GetNonce()) != 32 {
		return nil, status.Error(codes.InvalidArgument, "invalid reflection request")
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return nil, status.Error(codes.Unavailable, "reflection address unavailable")
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	address, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil {
		return nil, status.Error(codes.Unavailable, "reflection address unavailable")
	}
	state, ok := s.state.(interface {
		OnReflectAddress(context.Context, *Mutation, *pb.ReflectAddressRequest, string) (*pb.ReflectAddressResponse, error)
	})
	if !ok {
		return nil, status.Error(codes.Unimplemented, "address reflection unavailable")
	}
	return state.OnReflectAddress(ticket.Context(), ticket, in, address.Unmap().String())
}
