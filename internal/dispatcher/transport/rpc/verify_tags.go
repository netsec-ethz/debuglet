// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

// VerifyTags asks the executor about one packet group before disclosure
// (docs/verification.md, method server). It is not part of
// BoundExecutorClient, so a test double of that interface needs no change.
func (c *boundExecutorClient) VerifyTags(ctx context.Context, in *pb.VerifyTagsRequest, opts ...grpc.CallOption) (*pb.VerifyTagsResponse, error) {
	out, err := c.client.VerifyTags(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
