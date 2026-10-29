// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type experimentPeer struct {
	pb.UnimplementedDispatcherServiceServer
	ready func(context.Context, *pb.ExperimentReadyRequest) (*pb.ExperimentReadyResponse, error)
}

func (p experimentPeer) ExperimentReady(ctx context.Context, req *pb.ExperimentReadyRequest) (*pb.ExperimentReadyResponse, error) {
	return p.ready(ctx, req)
}

func TestExperimentRunBindingAndCancellation(t *testing.T) {
	id := uuid.New()
	calls := make(chan *pb.ExperimentReadyRequest, 2)
	peer := experimentPeer{ready: func(ctx context.Context, req *pb.ExperimentReadyRequest) (*pb.ExperimentReadyResponse, error) {
		calls <- req
		if string(req.Metadata) == "wait" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &pb.ExperimentReadyResponse{ExperimentId: "batch", StartTimeNs: time.Now().Add(time.Second).UnixNano(), Participants: []*pb.ExperimentParticipant{{Id: id.String(), ExecutorId: req.ExecutorId, Metadata: req.Metadata, ReadyAtNs: 123}}}, nil
	}}
	e, _ := newExecutorRPCFixture(t, peer, newFixtureMemoryStorage(t))
	control := runExperiment{executor: e, spec: scheduler.Spec{DebugletID: id, Binding: operationBinding()}}
	result, err := control.Ready(context.Background(), []byte("opaque"))
	if err != nil {
		t.Fatal(err)
	}
	req := <-calls
	if req.DebugletId != id.String() || req.ExecutorId != e.cfg.Identity.ExecutorID || result.ID != "batch" || len(result.Participants) != 1 || result.Participants[0].ReadyAtNS != 123 || string(result.Participants[0].Metadata) != "opaque" {
		t.Fatalf("incorrect request/result: %v %v", req, result)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	finished := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		_, err := control.Ready(ctx, []byte("wait"))
		finished <- err
	}()
	defer func() {
		cancel()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("readiness call did not join after cancellation")
		}
	}()
	select {
	case <-calls:
		cancel()
	case err := <-finished:
		t.Fatalf("readiness call ended before the handler started: %v", err)
	case <-ctx.Done():
		t.Fatalf("readiness handler did not start: %v", ctx.Err())
	}
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
			t.Fatalf("cancellation ignored: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readiness call did not return after cancellation")
	}
}

func TestExperimentReadinessSurvivesOneSlowPoll(t *testing.T) {
	id := uuid.New()
	requests := make(chan *pb.ExperimentReadyRequest, 2)
	var calls atomic.Int32
	peer := experimentPeer{ready: func(ctx context.Context, req *pb.ExperimentReadyRequest) (*pb.ExperimentReadyResponse, error) {
		requests <- req
		if calls.Add(1) == 1 {
			// Readiness may have committed before its response was lost.
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &pb.ExperimentReadyResponse{ExperimentId: "batch", StartTimeNs: time.Now().Add(time.Second).UnixNano()}, nil
	}}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	control := runExperiment{executor: e, spec: scheduler.Spec{DebugletID: id, Binding: operationBinding()}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	metadata := []byte("immutable readiness")
	pending, err := control.Ready(ctx, metadata)
	if err != nil || pending.ID != "" || pending.StartTimeNS != 0 || len(pending.Participants) != 0 {
		t.Fatalf("slow poll must remain pending: %+v %v", pending, err)
	}
	result, err := control.Ready(ctx, metadata)
	if err != nil || result.ID != "batch" || result.StartTimeNS == 0 {
		t.Fatalf("next poll did not observe release: %+v %v", result, err)
	}
	for range 2 {
		req := <-requests
		if req.DebugletId != id.String() || req.ExecutorId != e.cfg.Identity.ExecutorID || string(req.Metadata) != string(metadata) {
			t.Fatalf("retry changed readiness identity or metadata: %v", req)
		}
	}
}

func TestExperimentReadinessPreservesExpiryAndRefusal(t *testing.T) {
	for _, code := range []codes.Code{codes.DeadlineExceeded, codes.FailedPrecondition, codes.PermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			peer := experimentPeer{ready: func(context.Context, *pb.ExperimentReadyRequest) (*pb.ExperimentReadyResponse, error) {
				return nil, status.Error(code, "dispatcher refused readiness")
			}}
			e, _ := newExecutorRPCFixture(t, peer, nil)
			control := runExperiment{executor: e, spec: scheduler.Spec{DebugletID: uuid.New(), Binding: operationBinding()}}
			if _, err := control.Ready(t.Context(), nil); status.Code(err) != code {
				t.Fatalf("dispatcher refusal changed: %v", err)
			}
		})
	}
	t.Run("caller deadline", func(t *testing.T) {
		peer := experimentPeer{ready: func(ctx context.Context, _ *pb.ExperimentReadyRequest) (*pb.ExperimentReadyResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		e, _ := newExecutorRPCFixture(t, peer, nil)
		control := runExperiment{executor: e, spec: scheduler.Spec{DebugletID: uuid.New(), Binding: operationBinding()}}
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if _, err := control.Ready(ctx, nil); !errors.Is(err, context.DeadlineExceeded) && status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("caller expiry became a pending poll: %v", err)
		}
	})
}
