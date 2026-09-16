// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	pb "debuglet/protocol"
)

type ExecutorState interface {
	OnHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error)
	OnUpload(ctx context.Context, req *pb.UploadRequest) (*pb.UploadResponse, error)
	OnAbort(ctx context.Context, req *pb.AbortRequest) (*pb.AbortResponse, error)
	OnBandwidth(ctx context.Context, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error)
}
