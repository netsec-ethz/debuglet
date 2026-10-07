// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package testpeer

import (
	"context"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// OnVerifyTags forwards a pre-disclosure verification query to the script.
func (s ExecutorState) OnVerifyTags(ctx context.Context, _ controlsession.Binding, r *pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error) {
	return s.Service.VerifyTags(ctx, r)
}
