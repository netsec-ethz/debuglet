// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

func (c *boundExecutorClient) InspectRetainedRun(ctx context.Context, in *pb.InspectRetainedRunRequest, opts ...grpc.CallOption) (*pb.InspectRetainedRunResponse, error) {
	out, err := c.client.InspectRetainedRun(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
