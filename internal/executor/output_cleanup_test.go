// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

// Hold the canceled receive until cleanup has applied the pump cancellation.
// This makes the cleanup/transport race deterministic without changing either
// production deadline, and verifies that finish joins the outstanding call.
type cleanupHeldOutputClient struct {
	pb.DispatcherServiceClient
	release <-chan struct{}
}

func (c cleanupHeldOutputClient) DebugletStream(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[pb.DebugletStreamRequest, pb.DebugletStreamResponse], error) {
	stream, err := c.DispatcherServiceClient.DebugletStream(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return cleanupHeldOutputStream{stream, c.release}, nil
}

type cleanupHeldOutputStream struct {
	grpc.BidiStreamingClient[pb.DebugletStreamRequest, pb.DebugletStreamResponse]
	release <-chan struct{}
}

func (s cleanupHeldOutputStream) Recv() (*pb.DebugletStreamResponse, error) {
	receipt, err := s.BidiStreamingClient.Recv()
	if err != nil {
		<-s.release
	}
	return receipt, err
}

func TestDurableOutputCleanupTimeoutRetainsFinality(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		name := "complete_capture"
		if incomplete {
			name = "incomplete_capture"
		}
		t.Run(name, func(t *testing.T) {
			peer := newOperationPeer()
			held, cleanupApplied := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			var attempts atomic.Int32
			peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
				attempt := attempts.Add(1)
				if _, err := stream.Recv(); err != nil {
					return err
				}
				if err := stream.Send(&pb.DebugletStreamResponse{}); err != nil {
					return err
				}
				req, err := stream.Recv()
				if err != nil {
					return err
				}
				if req.GetOutput().GetSequence() != 1 || string(req.GetOutput().GetOutput()) != "retained result" {
					return errors.New("unexpected retained output")
				}
				if attempt == 1 {
					close(held)
					<-stream.Context().Done()
					return stream.Context().Err()
				}
				if err := stream.Send(&pb.DebugletStreamResponse{CommittedSequence: 1}); err != nil {
					return err
				}
				req, err = stream.Recv()
				if err != nil {
					return err
				}
				if req.GetEnd() == nil {
					return errors.New("missing retained end")
				}
				return stream.Send(&pb.DebugletStreamResponse{CommittedSequence: 1, End: req.GetEnd()})
			}
			e, _ := newExecutorRPCFixture(t, peer, nil)
			e.outputVersion.Store(pb.OutputVersion)
			clientFor := e.clientFor
			e.clientFor = func(ctx context.Context, binding controlsession.Binding) (pb.DispatcherServiceClient, error) {
				client, err := clientFor(ctx, binding)
				return cleanupHeldOutputClient{client, cleanupApplied}, err
			}
			op := newDebugletOperation(t.Context())
			spec := operationSpec()
			pump, err := e.newDurableOutput(op, spec)
			if err != nil {
				t.Fatal(err)
			}
			cancel := pump.cancel
			pump.cancel = func() {
				cancel()
				releaseOnce.Do(func() { close(cleanupApplied) })
			}
			t.Cleanup(func() {
				op.cancel(context.Canceled)
				pump.Cancel()
				operationJoinCleanup(t, pump.done, "durable output worker")
			})
			pump.Input <- []byte("retained result")
			if !operationAwait(t, held, "final frame awaiting acknowledgement") {
				pump.producerFinished(nil)
				return
			}
			var producerErr error
			if incomplete {
				producerErr = debuglet.ErrOutputIncomplete
			}
			done := make(chan struct{})
			go func() {
				op.finish(producerErr, pump)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2*scheduler.CleanupTimeout + operationTestBound):
				t.Fatal("cleanup did not join durable output")
			}
			if incomplete {
				if !errors.Is(op.outcome, producerErr) {
					t.Fatalf("capture failure was replaced: %v", op.outcome)
				}
			} else if !errors.Is(op.outcome, context.DeadlineExceeded) {
				t.Fatalf("cleanup timeout was hidden: %v", op.outcome)
			}
			retained, err := e.output.Get(t.Context(), spec.DebugletID)
			if err != nil || retained.End == nil || retained.End.LastSequence != 1 || retained.QueuedFrames != 1 || retained.EndAcknowledged {
				t.Fatalf("cleanup stranded accepted output: %+v %v", retained, err)
			}
			wantStatus, wantReason := pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, ""
			if incomplete {
				wantStatus, wantReason = pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, "producer_failed"
			}
			if retained.End.Status != wantStatus || retained.End.Reason != wantReason || e.outputFailed.Load() {
				t.Fatalf("cleanup changed capture status or poisoned storage: %+v", retained)
			}
			if err := e.deliverOutput(t.Context(), spec.Binding, retained); err != nil {
				t.Fatal(err)
			}
			retained, err = e.output.Get(t.Context(), spec.DebugletID)
			if err != nil || !retained.EndAcknowledged || retained.QueuedFrames != 0 || retained.QueuedBytes != 0 || attempts.Load() != 2 {
				t.Fatalf("retained output did not reconcile: %+v %v", retained, err)
			}
		})
	}
}

func TestDurableOutputReceiptStorageBoundsConnectionWait(t *testing.T) {
	db := newFixtureDatabase(t)
	store, err := outputstore.New(db, fixtureConfig().Output.Limits())
	if err != nil {
		t.Fatal(err)
	}
	e := &Executor{output: store}
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The only database connection stays occupied. SQLite's busy timeout
	// cannot bound callers that are still waiting in the Go connection pool.
	id := operationSpec().DebugletID
	calls := []func() error{
		func() error {
			return e.validateQuotaReceipt(t.Context(), id, &pb.DebugletStreamResponse{End: &pb.DebugletOutputEnd{
				Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, Reason: "storage_limit",
			}})
		},
		func() error { return e.acknowledgeOutput(t.Context(), id, &pb.DebugletStreamResponse{}) },
	}
	results := make(chan error, len(calls))
	for _, call := range calls {
		go func() { results <- call() }()
	}
	deadline := time.NewTimer(outputCallTimeout + operationTestBound)
	defer deadline.Stop()
	for range calls {
		select {
		case err := <-results:
			if !errors.Is(err, context.DeadlineExceeded) || t.Context().Err() != nil {
				t.Fatalf("receipt storage did not use its own deadline: %v", err)
			}
		case <-deadline.C:
			t.Fatal("receipt storage waited beyond its call budget")
		}
	}
}
