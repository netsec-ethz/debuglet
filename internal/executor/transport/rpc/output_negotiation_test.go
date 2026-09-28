// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"strconv"
	"testing"
	"time"
)

type outputNegotiationState struct{ negotiationState }

func (s *outputNegotiationState) OnHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	out, err := s.negotiationState.OnHello(ctx, in)
	if err == nil && in.GetOutputVersion() == pb.OutputVersion {
		out.OutputVersion = pb.OutputVersion
	}
	return out, err
}

func TestOutputHelloVersionIsImmutable(t *testing.T) {
	for _, version := range []uint32{0, pb.OutputVersion, 99} {
		t.Run(strconv.Itoa(int(version)), func(t *testing.T) {
			offer := negotiationOffer()
			offer.OutputVersion = version
			state := &outputNegotiationState{}
			f := newNegotiationFixture(t, state, offer, time.Second, func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
				return &pb.BindSessionResponse{LeaseDurationMs: offer.LeaseDurationMs}, nil
			})
			hello := f.helloResult()
			if hello.err != nil {
				t.Fatal(hello.err)
			}
			expected := uint32(0)
			if version == pb.OutputVersion {
				expected = pb.OutputVersion
			}
			if hello.response.OutputVersion != expected {
				t.Fatal("offer did not reach executor or echo was lost")
			}
			if _, err := hello.client.Hello(f.ctx, offer); err != nil {
				t.Fatal(err)
			}
			changed := proto.Clone(offer).(*pb.HelloRequest)
			changed.OutputVersion++
			if _, err := hello.client.Hello(f.ctx, changed); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("changed offer accepted: %v", err)
			}
		})
	}
}
