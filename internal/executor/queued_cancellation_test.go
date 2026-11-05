// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Use the real SQLite scheduler and Upload/Abort/Exit RPCs. The Abort caller
// disconnects while its queued cancellation reports; the owned callback must
// still deliver its durable terminal result without ever creating a guest.
func TestQueuedCancellationReportsAfterAbortCallerExpires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db := newFixtureDatabase(t)
	storage := newFixtureStorage(t, db, func(binding controlsession.Binding) bool { return binding == operationBinding() })
	peer := newOperationPeer()
	reporting, releaseReport := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseReport) }) }
	var reports, runtimes atomic.Int32
	peer.exit = func(ctx context.Context, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		if reports.Add(1) == 1 {
			close(reporting)
		}
		if req.ExitCode != -1 || req.GetErrorMessage() != "cancel queued upload" {
			t.Errorf("queued terminal report = %+v", req)
		}
		select {
		case <-releaseReport:
			return &pb.DebugletExitResponse{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e, client := newExecutorRPCFixture(t, peer, storage)
	e.newRuntime = func(scheduler.Spec) runtimeDebuglet { runtimes.Add(1); return &operationRuntime{} }
	t.Cleanup(func() {
		release()
		joined, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := storage.Shutdown(joined); err != nil {
			t.Error(err)
		}
	})
	id := uuid.New()
	req := boundsUploadRequest()
	req.Id = id.String()
	req.StartTime = timestamppb.New(time.Now().Add(time.Hour))
	if _, err := client.Upload(ctx, req); err != nil {
		t.Fatal(err)
	}
	abortCtx, stopAbort := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stopAbort()
	aborted := make(chan error, 1)
	go func() {
		_, err := client.Abort(abortCtx, &pb.AbortRequest{DebugletId: id.String(), Reason: "cancel queued upload"})
		aborted <- err
	}()
	if !operationAwait(t, reporting, "queued terminal report") {
		t.FailNow()
	}
	if err := <-aborted; status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("Abort caller = %v", err)
	}
	event, found, err := storage.RetainedTerminal(ctx, id)
	if err != nil || !found || event.ExitCode != -1 || event.Binding != operationBinding() {
		t.Fatalf("terminal not retained before acknowledgement: %+v %t %v", event, found, err)
	}
	release()
	// Join while the scheduler remains open, then prove an absent retry is
	// harmless because the terminal report has already completed.
	if _, err := storage.CancelBound(ctx, id, operationBinding(), context.Canceled); err != nil {
		t.Fatalf("join queued cancellation: %v", err)
	}
	if _, err := client.Abort(ctx, &pb.AbortRequest{DebugletId: id.String()}); status.Code(err) != codes.NotFound {
		t.Fatalf("removed run retry = %v", err)
	}
	if _, found, err := storage.RetainedTerminal(ctx, id); err != nil || found {
		t.Fatalf("acknowledged terminal retained: %t %v", found, err)
	}
	var rows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ?", id).Scan(&rows); err != nil || rows != 0 || reports.Load() != 1 || runtimes.Load() != 0 {
		t.Fatalf("queued cleanup: rows=%d reports=%d runtimes=%d error=%v", rows, reports.Load(), runtimes.Load(), err)
	}
}

// Concurrent guests and queued cancellation can report in either order.
func operationReports(t *testing.T, peer *operationPeer, ids ...string) map[string]*pb.DebugletExitRequest {
	t.Helper()
	remaining := make(map[string]bool, len(ids))
	for _, id := range ids {
		remaining[id] = true
	}
	result := make(map[string]*pb.DebugletExitRequest, len(ids))
	timer := time.NewTimer(operationTestBound)
	defer timer.Stop()
	for len(remaining) != 0 {
		select {
		case report := <-peer.reports:
			if !remaining[report.DebugletId] {
				t.Fatalf("unexpected or duplicate terminal report: %v", report)
			}
			result[report.DebugletId] = report
			delete(remaining, report.DebugletId)
		case <-timer.C:
			t.Fatalf("missing terminal reports: %v", remaining)
		}
	}
	return result
}
