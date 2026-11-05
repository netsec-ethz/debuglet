// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The HTTP caller disconnects after admission. One executor cancellation joins;
// the other consumes its entire delivery deadline. Local recording must still
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
	ids, err := f.d.SubmitDebuglets(request, specs, nil)
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
