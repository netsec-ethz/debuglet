// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestLowStoragePreservesRealGuestControlAndOutputFinality(t *testing.T) {
	peer := newOperationPeer()
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		if _, err := stream.Recv(); err != nil {
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
			receipt := &pb.DebugletStreamResponse{}
			if out := req.GetOutput(); out != nil {
				receipt.CommittedSequence = out.Sequence
			}
			if end := req.GetEnd(); end != nil {
				receipt.CommittedSequence = end.LastSequence
				receipt.End = end
			}
			if err = stream.Send(receipt); err != nil {
				return err
			}
		}
	}
	db := newFixtureDatabase(t)
	limits := outputstore.DefaultLimits()
	limits.ControlReserveBytes = 4096
	output, err := outputstore.New(db, limits)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := sqlite.NewStorage(db, output, func(binding controlsession.Binding) bool { return false }, fixtureAdmission(), scheduler.DefaultQueueLimits())
	if err != nil {
		t.Fatal(err)
	}
	e, control := newExecutorRPCFixture(t, peer, storage)
	e.output = output
	e.outputVersion.Store(pb.OutputVersion)
	guest, err := os.ReadFile("../../pkg/debuglet/testdata/abi_v1/abi_v1.wasm")
	if err != nil {
		t.Fatal(err)
	}
	spec, sibling := operationSpec(), operationSpec()
	spec.Policy.Timeout = 10 * time.Second
	sibling.Policy.Timeout = 10 * time.Second
	spec.Wasm, spec.Args = guest, []string{strings.Repeat("x", pb.MaxOutputFrameBytes-100)}
	sibling.Wasm, sibling.Args = guest, []string{"clock"}
	for _, run := range []scheduler.Spec{spec, sibling} {
		if err = output.Admit(t.Context(), run.DebugletID, run.Binding, pb.OutputVersion); err != nil {
			t.Fatal(err)
		}
	}
	var pages int64
	if err = db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages+30)); err != nil {
		t.Fatal(err)
	}
	call := startOperationTest(t, e, spec)
	select {
	case <-call.done:
	case <-time.After(10 * time.Second):
		t.Fatal("low-storage producer and terminal did not join")
	}
	if call.completion.CleanupErr != nil {
		t.Fatal(call.completion.CleanupErr)
	}
	report := operationReport(t, peer, spec.DebugletID)
	retained, err := output.Get(t.Context(), spec.DebugletID)
	if err != nil || retained.End == nil || retained.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED || retained.End.Reason != pb.OutputReasonSpoolLimit {
		t.Fatalf("storage finality=%+v,%v; terminal=%v", retained, err, report)
	}
	ctx, cancel := context.WithTimeout(t.Context(), operationTestBound)
	defer cancel()
	queued := boundsUploadRequest()
	queued.StartTime = timestamppb.New(time.Now().Add(time.Hour))
	if _, err = control.Upload(ctx, queued); err != nil {
		t.Fatal("control upload:", err)
	}
	if _, err = control.Abort(ctx, &pb.AbortRequest{DebugletId: queued.Id}); err != nil {
		t.Fatal("control abort:", err)
	}
	healthy := startOperationTest(t, e, sibling)
	select {
	case <-healthy.done:
	case <-time.After(10 * time.Second):
		t.Fatal("healthy guest did not join")
	}
	if healthy.completion.CleanupErr != nil {
		t.Fatal(healthy.completion.CleanupErr)
	}
	select {
	case report := <-peer.reports:
		if report.DebugletId != sibling.DebugletID.String() || report.ExitCode != 0 {
			t.Fatalf("healthy sibling failed: %v", report)
		}
	case <-time.After(operationTestBound):
		t.Fatal("healthy sibling terminal missing")
	}
	if peer.reportCalls.Load() != 2 {
		t.Fatal("unexpected terminal count")
	}

	retained, err = output.Get(t.Context(), sibling.DebugletID)
	if err != nil || retained.End == nil || retained.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE {
		t.Fatalf("sibling finality=%+v,%v", retained, err)
	}
}
