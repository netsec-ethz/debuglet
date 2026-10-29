// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type runExperiment struct {
	executor *Executor
	spec     scheduler.Spec
}

func (r runExperiment) Ready(ctx context.Context, metadata []byte) (wire.Experiment, error) {
	var result wire.Experiment
	if len(metadata) > wire.MaxExperimentMetadata {
		return result, status.Error(codes.ResourceExhausted, "experiment metadata exceeds limit")
	}
	pollCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	client, err := r.executor.dispatcherClient(pollCtx, r.spec.Binding)
	if err != nil {
		return result, err
	}
	reply, err := client.ExperimentReady(pollCtx, &pb.ExperimentReadyRequest{
		DebugletId: r.spec.DebugletID.String(), ExecutorId: r.executor.cfg.Identity.ExecutorID, Metadata: metadata,
	})
	if err != nil {
		if pollCtx.Err() == context.DeadlineExceeded && status.Code(err) == codes.DeadlineExceeded {
			// A slow poll does not expire the guest's readiness budget. The
			// dispatcher records immutable metadata, so the SDK may poll again
			// with the same run and metadata even if this reply was lost.
			if err := r.executor.checkExecutionLease(ctx, r.spec.Binding); err != nil {
				return result, err
			}
			return result, nil
		}
		return result, err
	}
	if err := r.executor.checkExecutionLease(ctx, r.spec.Binding); err != nil {
		return result, err
	}
	if reply == nil || len(reply.GetParticipants()) > wire.MaxExperimentParticipants {
		return result, status.Error(codes.ResourceExhausted, "invalid experiment response")
	}
	result.ID, result.StartTimeNS = reply.GetExperimentId(), reply.GetStartTimeNs()
	for _, p := range reply.GetParticipants() {
		if len(p.GetMetadata()) > wire.MaxExperimentMetadata {
			return wire.Experiment{}, status.Error(codes.ResourceExhausted, "experiment metadata exceeds limit")
		}
		result.Participants = append(result.Participants, wire.ExperimentParticipant{
			ID: p.GetId(), ExecutorID: p.GetExecutorId(), Metadata: p.GetMetadata(), ReadyAtNS: p.GetReadyAtNs(),
		})
	}
	return result, nil
}
