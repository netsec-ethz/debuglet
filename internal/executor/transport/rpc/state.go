// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// ExecutorState receives the immutable binding the reverse transport validated.
// An acknowledged RPC is not proof that the dispatcher finished anything.
type ExecutorState interface {
	OnHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error)
	OnUpload(ctx context.Context, binding controlsession.Binding, req *pb.UploadRequest) (*pb.UploadResponse, error)
	OnAbort(ctx context.Context, binding controlsession.Binding, req *pb.AbortRequest) (*pb.AbortResponse, error)
	OnBandwidth(ctx context.Context, binding controlsession.Binding, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error)
}

// CheckPayloadBinding compares the immutable binding a request carries with the
// session that was admitted, which is the one rule for every request that names
// its own session. It decides nothing about possession: the transport
// authenticates the caller's credentials first, and the state rechecks its lease
// at the moment an effect commits. Callers that reach a handler directly apply
// it themselves, so the rule does not depend on which path a request took.
func CheckPayloadBinding(supplied *pb.ControlBinding, admitted controlsession.Binding) error {
	payload, err := controlsession.ParseBinding(supplied.GetDispatcherIncarnation(), supplied.GetSessionId())
	if err != nil {
		return controlrpc.Malformed()
	}
	if payload != admitted {
		return controlrpc.Denied()
	}
	return nil
}
