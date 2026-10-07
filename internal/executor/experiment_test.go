// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
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
