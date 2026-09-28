// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type refusedOutputPeer struct{ *fbPeer }

func (p *refusedOutputPeer) Hello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	response, err := p.tgPeer.Hello(ctx, req)
	response.OutputVersion = pb.OutputVersion
	return response, err
}

func refusedOutputFixture(t *testing.T) (*tgFixture, *fbPeer) {
	t.Helper()
	d := newTerminalPeerDispatcher(t)
	ctx, cancel := context.WithTimeout(t.Context(), tgBound)
	t.Cleanup(cancel)
	peer := &fbPeer{tgPeer: &tgPeer{}, answer: make(map[string]error)}
	stop, err := startTerminalPeer(ctx, d, tgCapacity, &refusedOutputPeer{peer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), tgBound)
		defer cancel()
		if err := stop(cleanup); err != nil {
			t.Error(err)
		}
	})
	return &tgFixture{ctx: ctx, d: d, db: d.db, q: database.New(d.db), ph: d.Payment, peer: peer.tgPeer, start: time.Now().Add(time.Hour).Truncate(time.Second)}, peer
}

func TestRefusedUploadFinalizesOnlyItsProvenEmptyOutput(t *testing.T) {
	f, peer := refusedOutputFixture(t)
	specA, specB := f.spec(t, tgFloorA), f.spec(t, tgFloorB)
	both := make(chan struct{})
	var mu sync.Mutex
	ids := make(map[string]uuid.UUID)
	peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
		id, err := parseRunID(req.GetId())
		if err != nil {
			return err
		}
		peer.refuse(req.GetId(), status.Error(codes.NotFound, "run absent"))
		mu.Lock()
		ids[req.GetTransactionId()] = id
		if len(ids) == 2 {
			close(both)
		}
		mu.Unlock()
		if req.GetTransactionId() == specA.TransactionID {
			select {
			case <-both:
				return status.Error(codes.FailedPrecondition, "upload refused")
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if _, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{specA, specB}, nil); err == nil {
		t.Fatal("failed upload was accepted")
	}
	mu.Lock()
	a, b := ids[specA.TransactionID], ids[specB.TransactionID]
	mu.Unlock()
	refused, err := f.q.GetDebugletOutput(f.ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if refused.Status != "complete" || !refused.FinalSequence.Valid || refused.FinalSequence.Int64 != 0 || !refused.FinalCursor.Valid || refused.FinalCursor.Int64 != 0 || refused.ByteCount != 0 || refused.FrameCount != 0 {
		t.Fatalf("definitely refused output remains incomplete: %+v", refused)
	}
	ambiguous, err := f.q.GetDebugletOutput(f.ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if ambiguous.Status != "pending" || ambiguous.FinalSequence.Valid || ambiguous.FinalCursor.Valid {
		t.Fatalf("canceled sibling acquired finality from NotFound alone: %+v", ambiguous)
	}
	tgAssertRow(t, f.row(t, a), models.RunStateExited, tgText("failed to batch upload all debuglets"))
	tgAssertRow(t, f.row(t, b), models.RunStateUnreconciled, tgNull)
}

func TestRefusedUploadOutputFailureKeepsTerminalResult(t *testing.T) {
	f, peer := refusedOutputFixture(t)
	if _, err := f.db.ExecContext(f.ctx, `CREATE TRIGGER refuse_output_end BEFORE UPDATE OF final_sequence ON debuglet_output BEGIN SELECT RAISE(ABORT, 'output end unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	a, _ := fbSubmitFailedBatch(t, f, peer, status.Error(codes.NotFound, "run absent"), status.Error(codes.FailedPrecondition, "upload refused"), false)
	tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("failed to batch upload all debuglets"))
	row, err := f.q.GetDebugletOutput(f.ctx, a.id)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != "pending" || row.FinalSequence.Valid || row.FinalCursor.Valid {
		t.Fatalf("failed output write fabricated finality: %+v", row)
	}
}

func TestRefusedOutputPreservesPrefixFinalityAndOwnership(t *testing.T) {
	f := newOutputTLS(t)
	_, owner := f.connect(f.identity, true)
	writer, err := outputWriterFor(owner, &pb.ControlBinding{DispatcherIncarnation: owner.Binding().Incarnation, SessionId: owner.Binding().SessionID})
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := owner.AdmitMutation(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mutation.Finish()
	for _, kind := range []string{"prefix", "empty frame", "complete", "truncated", "wrong binding"} {
		t.Run(kind, func(t *testing.T) {
			id := outputTestRun(t, f.d, writer, nil)
			switch kind {
			case "prefix":
				requireOutputReceipt(t, f.d, writer, id, outputFrame(1, "retained"), nil)
			case "empty frame":
				requireOutputReceipt(t, f.d, writer, id, outputFrame(1, ""), nil)
			case "complete":
				requireOutputReceipt(t, f.d, writer, id, nil, &pb.DebugletOutputEnd{Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE})
			case "truncated":
				requireOutputReceipt(t, f.d, writer, id, nil, &pb.DebugletOutputEnd{Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, Reason: pb.OutputReasonProducerFailed})
			case "wrong binding":
				if _, err := f.d.db.ExecContext(f.ctx, "UPDATE debuglets SET session_id = ? WHERE uuid = ?", uuid.NewString(), id); err != nil {
					t.Fatal(err)
				}
			}
			q := database.New(f.d.db)
			before, err := q.GetDebugletOutput(f.ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			err = f.d.finishRefusedOutput(f.ctx, mutation, id)
			if kind == "wrong binding" {
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("wrong ownership: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			after, err := q.GetDebugletOutput(f.ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatalf("existing output changed: before=%+v after=%+v", before, after)
			}
		})
	}
	id := outputTestRun(t, f.d, writer, nil)
	mutation.Finish()
	if err := f.d.finishRefusedOutput(f.ctx, mutation, id); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("finished mutation authorized finality: %v", err)
	}
	row, err := database.New(f.d.db).GetDebugletOutput(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.FinalSequence.Valid || row.FinalCursor.Valid {
		t.Fatalf("lost mutation fabricated finality: %+v", row)
	}
}
