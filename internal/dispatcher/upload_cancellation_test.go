// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The HTTP caller disconnects after admission and delivery later times out.
// One executor cancellation joins; the other consumes its delivery deadline. Local recording must still
// work, and the slow call must not prevent its sibling from being cancelled.
func TestDisconnectedSubmissionRecordsCancellationTimeout(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	request, disconnect := context.WithCancel(f.ctx)
	defer disconnect()
	specs := f.batch(t, tgFloorA, tgFloorB)
	var uploads atomic.Int32
	var stalled atomic.Value
	peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
		if req.GetPolicy().GetFloorBw() == int64(tgFloorA) {
			stalled.Store(req.GetId())
		}
		if uploads.Add(1) == 2 {
			disconnect()
		}
		<-ctx.Done()
		return status.FromContextError(ctx.Err()).Err()
	})
	peer.beforeAbort = func(ctx context.Context, req *pb.AbortRequest) error {
		if req.GetDebugletId() == stalled.Load().(string) {
			<-ctx.Done()
			return status.FromContextError(ctx.Err()).Err()
		}
		return nil
	}
	ids, err := f.d.submitDebuglets(request, specs, nil, 500*time.Millisecond)
	if !errors.Is(err, ErrAdmissionCommitted) || len(ids) != 2 {
		t.Fatalf("submission = %v, %v", ids, err)
	}
	stalledID := uuid.MustParse(stalled.Load().(string))
	for _, id := range ids {
		disposition, err := f.d.Cancellation(f.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if id == stalledID {
			tgAssertRow(t, f.row(t, id), models.RunStateUnreconciled, tgNull)
			if disposition.Disposition != "unresolved" || disposition.Reason != "transport_outcome_unknown" || disposition.AcknowledgedAt != nil {
				t.Fatalf("unconfirmed cancellation = %+v", disposition)
			}
		} else {
			tgAssertRow(t, f.row(t, id), models.RunStateExited, tgText("failed to batch upload all debuglets"))
			if disposition.Disposition != "acknowledged" || disposition.AcknowledgedAt == nil {
				t.Fatalf("confirmed sibling cancellation = %+v", disposition)
			}
		}
	}
	tgAssertReserved(t, f, tgDebuglet{id: stalledID, row: f.row(t, stalledID)}, tgFloorA)
	// A later NotFound is not evidence that a timed-out upload was rejected.
	peer.mu.Lock()
	peer.beforeAbort = nil
	peer.abortErr = status.Error(codes.NotFound, "already removed")
	peer.mu.Unlock()
	if err := f.abort(t, stalledID, "retry cancellation"); !errors.Is(err, ErrAbortRefused) {
		t.Fatalf("unconfirmed retry = %v", err)
	}
	tgAssertRow(t, f.row(t, stalledID), models.RunStateUnreconciled, tgNull)
	// The executor's durable late cancellation result settles the run exactly
	// once, even if its original Upload acknowledgement was never observed.
	reason := "failed to batch upload all debuglets"
	if err := f.exit(t, stalledID, -1, &reason); err != nil {
		t.Fatal(err)
	}
	tgAssertRow(t, f.row(t, stalledID), models.RunStateExited, tgText(reason))
	tgAssertReserved(t, f, tgDebuglet{id: stalledID, row: f.row(t, stalledID)}, 0)
	before := f.snapshot(t)
	if err := f.exit(t, stalledID, 0, nil); err != nil {
		t.Fatal(err)
	}
	tgAssertSnapshot(t, f, before, "late duplicate terminal result")
	repeated, err := f.d.SubmitDebuglets(f.ctx, specs, nil)
	if err != nil || len(repeated) != len(ids) || repeated[0] != ids[0] || repeated[1] != ids[1] || len(peer.recordedUploads()) != 2 {
		t.Fatalf("receipt retry created work: %v %v", repeated, err)
	}
}

// Cancel in the commit-to-upload gap, before any upload goroutine can fork its
// continuation. Both the durable receipt and the pending uploads must survive.
func TestSubmissionDisconnectAfterCommitBeforeUpload(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	request, disconnect := context.WithCancel(f.ctx)
	defer disconnect()
	core, _ := observer.New(zap.InfoLevel)
	f.d.logger = zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message == "Run admitted" {
			disconnect()
		}
		return nil
	}))
	specs := f.batch(t, tgFloorA, tgFloorB)
	ids, err := f.d.SubmitDebuglets(request, specs, nil)
	if err != nil || len(ids) != 2 || !errors.Is(request.Err(), context.Canceled) {
		t.Fatalf("submission after disconnect = %v, %v; request = %v", ids, err, request.Err())
	}
	for _, id := range ids {
		tgAssertRow(t, f.row(t, id), models.RunStateUploaded, tgNull)
	}
	if len(peer.recordedAborts()) != 0 {
		t.Fatal("browser disconnect cancelled accepted work")
	}
	repeated, err := f.d.SubmitDebuglets(f.ctx, specs, nil)
	if err != nil || len(repeated) != 2 || repeated[0] != ids[0] || repeated[1] != ids[1] || len(peer.recordedUploads()) != 2 {
		t.Fatalf("receipt retry replayed work: %v, %v", repeated, err)
	}
}

func TestSubmissionDisconnectStillAllowsExplicitCancellation(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	request, disconnect := context.WithCancel(f.ctx)
	defer disconnect()
	admitted, release := make(chan string, 1), make(chan struct{}, 1)
	defer close(release)
	peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
		admitted <- req.GetId()
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		}
	})
	done := make(chan error, 1)
	spec := f.spec(t, tgFloorA)
	go func() { _, err := f.d.SubmitDebuglets(request, []models.DebugletSpec{spec}, nil); done <- err }()
	var id uuid.UUID
	select {
	case text := <-admitted:
		id = uuid.MustParse(text)
	case <-f.ctx.Done():
		t.Fatal("upload did not enter")
	}
	disconnect()
	if err := f.abort(t, id, "cancelled via API"); err != nil {
		t.Fatalf("explicit cancellation after disconnect: %v", err)
	}
	// The peer accepted the cancellation before returning its delayed Upload
	// acknowledgement. That late success must not resurrect the terminal run.
	release <- struct{}{}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("upload acknowledgement: %v", err)
		}
	case <-f.ctx.Done():
		t.Fatal("submission did not finish")
	}
	tgAssertRow(t, f.row(t, id), models.RunStateExited, tgText("cancelled via API"))
	tgAssertReserved(t, f, tgDebuglet{id: id, row: f.row(t, id)}, 0)
	if len(peer.recordedAborts()) != 1 {
		t.Fatal("explicit cancellation was not delivered exactly once")
	}
}

func TestSubmissionDisconnectStillJoinsOnDispatcherClose(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	request, disconnect := context.WithCancel(f.ctx)
	defer disconnect()
	entered := make(chan struct{})
	peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
		close(entered)
		<-ctx.Done()
		return status.FromContextError(ctx.Err()).Err()
	})
	f.d.mu.RLock()
	owner := f.d.executors[tgExecutorID].owner
	f.d.mu.RUnlock()
	done := make(chan error, 1)
	spec := f.spec(t, tgFloorA)
	go func() { _, err := f.d.SubmitDebuglets(request, []models.DebugletSpec{spec}, nil); done <- err }()
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal("upload did not enter")
	}
	disconnect()
	closed := make(chan struct{})
	go func() { f.d.Close(); close(closed) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrAdmissionCommitted) {
			t.Fatalf("shutdown upload result: %v", err)
		}
	case <-f.ctx.Done():
		t.Fatal("shutdown did not cancel upload")
	}
	select {
	case <-closed:
	case <-f.ctx.Done():
		t.Fatal("dispatcher did not join upload and cleanup")
	}
	select {
	case <-owner.MutationsDrained():
	default:
		t.Fatal("post-admission continuation leaked after shutdown")
	}
}
