// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"io"
	"testing"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

func TestDurableOutputSlowReceiptLeavesControlAndSiblingHeadroom(t *testing.T) {
	peer := newOperationPeer()
	first := operationSpec()
	first.Policy.Timeout = time.Minute
	blocked, filled := make(chan struct{}), make(chan struct{})
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		ident, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(&pb.DebugletStreamResponse{}); err != nil {
			return err
		}
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if ident.GetIdent().GetDebugletId() == first.DebugletID.String() {
				close(blocked)
				<-stream.Context().Done()
				return stream.Context().Err()
			}
			receipt := &pb.DebugletStreamResponse{}
			if out := req.GetOutput(); out != nil {
				receipt.CommittedSequence = out.Sequence
			}
			if end := req.GetEnd(); end != nil {
				receipt.CommittedSequence = end.LastSequence
				receipt.End = end
			}
			if err := stream.Send(receipt); err != nil {
				return err
			}
		}
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	e.outputVersion.Store(pb.OutputVersion)
	runtime := &operationRuntime{run: func(ctx context.Context, out chan<- []byte) error {
		// One frame is held in transmission; exactly sixteen more fit in memory.
		for i := 0; i < outputQueueFrames+1; i++ {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case out <- make([]byte, pb.MaxOutputFrameBytes):
			}
		}
		close(filled)
		<-ctx.Done()
		return context.Cause(ctx)
	}}
	installOperationRuntime(e, first, runtime)
	call := startOperationTest(t, e, first)
	if !operationAwait(t, blocked, "slow output receipt") || !operationAwait(t, filled, "bounded output queue") {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), operationTestBound)
	defer cancel()
	control, err := e.dispatcherClient(ctx, first.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DebugletAllocate(ctx, &pb.DebugletAllocateRequest{}); err != nil {
		t.Fatal("management traffic blocked behind output:", err)
	}
	second := operationSpec()
	installOperationRuntime(e, second, &operationRuntime{run: func(ctx context.Context, out chan<- []byte) error { out <- []byte("sibling"); return nil }})
	sibling := startOperationTest(t, e, second)
	if !operationAwait(t, sibling.done, "sibling under slow output") {
		return
	}
	output, err := e.output.Get(t.Context(), second.DebugletID)
	if err != nil || !output.EndAcknowledged {
		t.Fatalf("sibling output unavailable: %+v %v", output, err)
	}
	call.cancel(context.Canceled)
	if !operationAwait(t, call.done, "blocked producer and output join") {
		return
	}
	retained, err := e.output.Get(t.Context(), first.DebugletID)
	if err != nil || retained.LastSequence != outputQueueFrames+1 || retained.End == nil || retained.EndAcknowledged {
		t.Fatalf("bounded queued prefix was lost: %+v %v", retained, err)
	}
}
