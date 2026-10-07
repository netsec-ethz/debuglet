// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := control.Ready(ctx, []byte("wait")); status.Code(err) != codes.DeadlineExceeded && ctx.Err() == nil {
		t.Fatalf("cancellation ignored: %v", err)
	}
	<-calls
}
