// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

func TestDurableOutputRateDeadlineDoesNotBypassBackpressure(t *testing.T) {
	peer := newOperationPeer()
	var delivered atomic.Int64
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			receipt := &pb.DebugletStreamResponse{CommittedSequence: delivered.Load()}
			if out := req.GetOutput(); out != nil {
				delivered.Store(out.Sequence)
				receipt.CommittedSequence = out.Sequence
			}
			if end := req.GetEnd(); end != nil {
				receipt.End = end
			}
			if err := stream.Send(receipt); err != nil {
				return err
			}
		}
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	e.outputVersion.Store(pb.OutputVersion)
	e.cfg.Output.RateBytesPerSecond = 1
	e.cfg.Output.BurstBytes = pb.MaxOutputFrameBytes
	// Refilling one frame takes hours, so WaitN refuses the future deadline
	// immediately while this context is still live.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	op := newDebugletOperation(ctx)
	defer op.cancel(nil)
	spec := operationSpec()
	pump, err := e.newDurableOutput(op, spec)
	if err != nil {
		t.Fatal(err)
	}
	pump.Input <- make([]byte, pb.MaxOutputFrameBytes)
	pump.Input <- make([]byte, pb.MaxOutputFrameBytes)
	close(pump.Input)
	op.finish(nil, pump)
	retained, err := e.output.Get(t.Context(), spec.DebugletID)
	if err != nil || retained.LastSequence != 2 || retained.End == nil || retained.EndAcknowledged || delivered.Load() > 1 || pump.err == nil {
		t.Fatalf("rate deadline bypassed or dropped accepted output: delivered=%d retained=%+v err=%v", delivered.Load(), retained, err)
	}
}

func TestDurableOutputRejectsMalformedQuotaWithoutInventingLoss(t *testing.T) {
	for _, tc := range []struct {
		name            string
		committed, last int64
	}{{"ahead", 100, 100}, {"mismatched", 0, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newOperationPeer()
			peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
				if _, err := stream.Recv(); err != nil {
					return err
				}
				if err := stream.Send(&pb.DebugletStreamResponse{}); err != nil {
					return err
				}
				if _, err := stream.Recv(); err != nil {
					return err
				}
				return stream.Send(&pb.DebugletStreamResponse{CommittedSequence: tc.committed, End: &pb.DebugletOutputEnd{LastSequence: tc.last, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, Reason: "storage_limit"}})
			}
			e, _ := newExecutorRPCFixture(t, peer, nil)
			e.outputVersion.Store(pb.OutputVersion)
			op := newDebugletOperation(t.Context())
			defer op.cancel(nil)
			spec := operationSpec()
			pump, err := e.newDurableOutput(op, spec)
			if err != nil {
				t.Fatal(err)
			}
			pump.Input <- []byte("retained")
			close(pump.Input)
			op.finish(nil, pump)
			retained, err := e.output.Get(t.Context(), spec.DebugletID)
			if err != nil || !errors.Is(pump.err, outputstore.ErrAcknowledgement) || retained.End == nil || retained.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE || retained.End.Reason != "" || retained.Receipt != nil || retained.QueuedFrames != 1 {
				t.Fatalf("invalid quota invented durable loss: %+v pump=%v err=%v", retained, pump.err, err)
			}
		})
	}
}
