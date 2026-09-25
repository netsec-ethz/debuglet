// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "modernc.org/sqlite"
)

// fbPeer is the scripted executor with one Abort answer per run: a run with a
// scripted answer is refused with it, every other Abort goes to tgPeer.
type fbPeer struct {
	*tgPeer
	mu     sync.Mutex
	answer map[string]error
}

func (p *fbPeer) refuse(id string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer[id] = err
}

func (p *fbPeer) Abort(ctx context.Context, req *pb.AbortRequest) (*pb.AbortResponse, error) {
	p.mu.Lock()
	err := p.answer[req.GetDebugletId()]
	p.mu.Unlock()
	if err == nil {
		return p.tgPeer.Abort(ctx, req)
	}
	p.tgPeer.mu.Lock()
	p.tgPeer.aborts = append(p.tgPeer.aborts, req)
	p.tgPeer.mu.Unlock()
	return nil, err
}

// newFBFixture is newTGFixture's transport variant for a peer that answers
// Abort per run.
func newFBFixture(t *testing.T, peer *fbPeer) *tgFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), tgBound)
	t.Cleanup(cancel)
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=synchronous(OFF)", filepath.Join(t.TempDir(), "failed-batch.sqlite")))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close sqlite: %v", err)
		}
	})
	testutil.ApplyMigrations(t, db, tgMigrations)
	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := New(logger, db, "fb-test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	stop, err := startTerminalPeer(ctx, d, tgCapacity, peer)
	if err != nil {
		t.Fatalf("startTerminalPeer: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancelStop := context.WithTimeout(context.Background(), tgBound)
		defer cancelStop()
		if err := stop(stopCtx); err != nil {
			t.Errorf("stop peer: %v", err)
		}
	})
	return &tgFixture{ctx: ctx, db: db, q: database.New(db), ph: ph, d: d, peer: peer.tgPeer, start: time.Now().Add(time.Hour).Truncate(time.Second)}
}

// fbWaitState polls the stored state of a run from a peer handler, where the
// test's Fatal helpers do not apply.
func fbWaitState(ctx context.Context, db *sql.DB, id string, want models.DebugletRunState) error {
	for {
		var state models.DebugletRunState
		if err := db.QueryRowContext(ctx, "SELECT state FROM debuglets WHERE uuid = ?", id).Scan(&state); err == nil && state == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("debuglet %s did not reach %s: %w", id, want, ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// fbSubmitFailedBatch submits a two-run batch. Without ownUpload, the first
// run is uploaded and, once it is stored as Uploaded (or after started ran
// for it), the second upload fails. With ownUpload, the second run is
// uploaded and, once it is stored as Uploaded, the first upload fails with
// ownUpload. The first run's Abort is answered with refusal, the second's is
// acknowledged. It returns both runs with their stored windows.
func fbSubmitFailedBatch(t *testing.T, f *tgFixture, peer *fbPeer, refusal, ownUpload error, started bool) (tgDebuglet, tgDebuglet) {
	t.Helper()
	specA, specB := f.spec(t, tgFloorA), f.spec(t, tgFloorB)
	var mu sync.Mutex
	ids := map[string]string{}
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
		mu.Lock()
		ids[req.GetTransactionId()] = req.GetId()
		mu.Unlock()
		if ownUpload != nil {
			if req.GetTransactionId() != specA.TransactionID {
				close(secondDone)
				return nil
			}
			peer.refuse(req.GetId(), refusal)
			select {
			case <-secondDone:
			case <-ctx.Done():
				return ctx.Err()
			}
			mu.Lock()
			second := ids[specB.TransactionID]
			mu.Unlock()
			waitCtx, cancel := context.WithTimeout(ctx, tgCallBound)
			defer cancel()
			if err := fbWaitState(waitCtx, f.db, second, models.RunStateUploaded); err != nil {
				return status.Error(codes.Internal, err.Error())
			}
			return ownUpload
		}
		switch req.GetTransactionId() {
		case specA.TransactionID:
			peer.refuse(req.GetId(), refusal)
			if started {
				id, _ := parseRunID(req.GetId())
				if err := f.state(t, id, pb.RunState_RUN_STATE_STARTED); err != nil {
					t.Errorf("report started: %v", err)
				}
			}
			close(firstDone)
			return nil
		default:
			select {
			case <-firstDone:
			case <-ctx.Done():
				return ctx.Err()
			}
			mu.Lock()
			first := ids[specA.TransactionID]
			mu.Unlock()
			want := models.RunStateUploaded
			if started {
				want = models.RunStateStarted
			}
			waitCtx, cancel := context.WithTimeout(ctx, tgCallBound)
			defer cancel()
			if err := fbWaitState(waitCtx, f.db, first, want); err != nil {
				return status.Error(codes.Internal, err.Error())
			}
			return status.Error(codes.Internal, "executor rejected the upload")
		}
	})
	got, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{specA, specB}, nil)
	if err == nil || got != nil {
		t.Fatalf("SubmitDebuglets = %v, %v; want no IDs and an error", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	runs := [2]tgDebuglet{}
	for i, spec := range []models.DebugletSpec{specA, specB} {
		id, parseErr := parseRunID(ids[spec.TransactionID])
		if parseErr != nil {
			t.Fatalf("run of %s was not uploaded: %v", spec.TransactionID, parseErr)
		}
		runs[i] = tgDebuglet{id: id, txID: spec.TransactionID, orderID: spec.OrderID, floor: spec.Policy.FloorBW, row: f.row(t, id)}
	}
	for _, deb := range runs {
		n := 0
		for _, up := range peer.recordedUploads() {
			if up.GetId() == deb.id.String() {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("run %s was uploaded %d times, want once", deb.id, n)
		}
	}
	return runs[0], runs[1]
}

// TestFailedBatchRefusedCancellation pins the disposition of a run whose
// executor answered the failed batch's cancellation with a refusal: it is
// stored as unreconciled, keeps its reservation, and its later real report
// still wins. A transport failure of the cancellation is left as it is.
func TestFailedBatchRefusedCancellation(t *testing.T) {
	const batchReason = "failed to batch upload all debuglets"
	for _, tc := range []struct {
		name      string
		refusal   error
		ownUpload error
		started   bool
		want      models.DebugletRunState
	}{
		{"not found", status.Error(codes.NotFound, "debuglet not found"), nil, false, models.RunStateUnreconciled},
		{"permission denied", status.Error(codes.PermissionDenied, "bound to another session"), nil, false, models.RunStateUnreconciled},
		{"already started", status.Error(codes.NotFound, "debuglet not found"), nil, true, models.RunStateStarted},
		{"transport failure", status.Error(codes.Unavailable, "connection lost"), nil, false, models.RunStateUploaded},
		{"own upload refused", status.Error(codes.NotFound, "debuglet not found"), status.Error(codes.FailedPrecondition, "upload refused"), false, models.RunStateExited},
		{"own upload refused, abort denied", status.Error(codes.PermissionDenied, "bound to another session"), status.Error(codes.FailedPrecondition, "upload refused"), false, models.RunStateUnreconciled},
		{"own upload unavailable", status.Error(codes.NotFound, "debuglet not found"), status.Error(codes.Unavailable, "connection lost"), false, models.RunStateUnreconciled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}
			f := newFBFixture(t, peer)
			a, b := fbSubmitFailedBatch(t, f, peer, tc.refusal, tc.ownUpload, tc.started)

			tgAssertRow(t, f.row(t, b.id), models.RunStateExited, tgText(batchReason))
			if aborts := peer.recordedAborts(); len(aborts) != 2 {
				t.Fatalf("peer recorded %d aborts, want 2", len(aborts))
			}
			if tc.want == models.RunStateExited {
				// A run the executor refused at upload and does not know at the
				// cancellation is finished by the batch failure, once.
				tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText(batchReason))
				tgAssertReserved(t, f, a, 0)
				after := f.snapshot(t)
				if err := f.exit(t, a.id, 3, nil); err != nil {
					t.Fatalf("late exit A: %v", err)
				}
				tgAssertSnapshot(t, f, after, "late exit")
				tgAssertReserved(t, f, a, 0)
				return
			}
			tgAssertRow(t, f.row(t, a.id), tc.want, tgNull)
			tgAssertReserved(t, f, a, tgFloorA)

			// The executor's real exit report supersedes the disposition once.
			if err := f.exit(t, a.id, 3, nil); err != nil {
				t.Fatalf("exit A: %v", err)
			}
			tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("debuglet exited with code 3"))
			tgAssertReserved(t, f, a, 0)
			after := f.snapshot(t)
			if err := f.exit(t, a.id, 4, nil); err != nil {
				t.Fatalf("duplicate exit A: %v", err)
			}
			tgAssertSnapshot(t, f, after, "duplicate exit")
			tgAssertReserved(t, f, a, 0)
		})
	}

	t.Run("later state report wins", func(t *testing.T) {
		peer := &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}
		f := newFBFixture(t, peer)
		a, _ := fbSubmitFailedBatch(t, f, peer, status.Error(codes.NotFound, "debuglet not found"), nil, false)
		tgAssertRow(t, f.row(t, a.id), models.RunStateUnreconciled, tgNull)
		if err := f.state(t, a.id, pb.RunState_RUN_STATE_INITIALIZING); err != nil {
			t.Fatalf("report initializing: %v", err)
		}
		tgAssertRow(t, f.row(t, a.id), models.RunStateInitializing, tgNull)
		tgAssertReserved(t, f, a, tgFloorA)
	})
}

// TestRunStateRankMatchesStateUpdate checks that SemanticRank follows the
// lifecycle and that the guarded UpdateDebugletState orders stored states the
// same way.
func TestRunStateRankMatchesStateUpdate(t *testing.T) {
	lifecycle := []models.DebugletRunState{
		models.RunStateUnspecified, models.RunStateUploading, models.RunStateUploaded, models.RunStateUnreconciled,
		models.RunStateInitializing, models.RunStateStarted, models.RunStateExited,
	}
	for i := 1; i < len(lifecycle); i++ {
		if lifecycle[i-1].SemanticRank() >= lifecycle[i].SemanticRank() {
			t.Fatalf("rank of %s (%d) is not below rank of %s (%d)", lifecycle[i-1], lifecycle[i-1].SemanticRank(), lifecycle[i], lifecycle[i].SemanticRank())
		}
	}
	if models.RunStateUnreconciled != 6 || models.RunStateUnreconciled.String() != "RunStateUnreconciled" {
		t.Fatalf("RunStateUnreconciled is %d %q, want stored value 6", int(models.RunStateUnreconciled), models.RunStateUnreconciled.String())
	}

	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	for _, from := range lifecycle {
		for _, to := range lifecycle {
			if _, err := f.db.Exec("UPDATE debuglets SET state = ? WHERE uuid = ?", from, run.id); err != nil {
				t.Fatalf("set state %s: %v", from, err)
			}
			_, err := f.q.UpdateDebugletState(f.ctx, database.UpdateDebugletStateParams{
				State: to, StateRank: to.SemanticRank(), Uuid: run.id, ExitedState: models.RunStateExited,
				ExecutorID: run.row.ExecutorID, DispatcherIncarnation: run.row.DispatcherIncarnation, SessionID: run.row.SessionID,
			})
			applied := err == nil
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("update %s -> %s: %v", from, to, err)
			}
			if want := from != models.RunStateExited && from.SemanticRank() < to.SemanticRank(); applied != want {
				t.Errorf("update %s -> %s applied=%v, want %v", from, to, applied, want)
			}
		}
	}
}
