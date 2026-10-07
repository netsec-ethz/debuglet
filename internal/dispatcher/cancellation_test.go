// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCancellationRequestMustCommitBeforeEffects(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	run, err := f.submit(t, tgFloorA)
	if err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	// A deferred constraint fails at COMMIT, after the INSERT itself succeeds.
	cleanupExec(t, f, `CREATE TABLE cancel_commit_guard (parent INTEGER REFERENCES debuglets(id) DEFERRABLE INITIALLY DEFERRED)`)
	cleanupExec(t, f, `CREATE TRIGGER cancel_commit_failure AFTER INSERT ON debuglet_cancellations BEGIN INSERT INTO cancel_commit_guard VALUES (-1); END`)
	if err := f.abort(t, run.id, "first reason"); status.Code(err) != codes.Internal {
		t.Fatalf("commit failure: %v", err)
	}
	if _, err := f.q.GetCancellation(f.ctx, run.row.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("uncommitted request: %v", err)
	}
	if len(peer.recordedAborts()) != 0 {
		t.Fatal("Abort preceded request commit")
	}
	tgAssertSnapshot(t, f, before, "failed cancellation request commit")
	cleanupExec(t, f, `DROP TRIGGER cancel_commit_failure`)
	if err := f.abort(t, run.id, "first reason"); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationTerminalAndObligationCommitTogether(t *testing.T) {
	for name, trigger := range map[string]string{
		"refused marker": `CREATE TRIGGER refuse_terminal BEFORE UPDATE OF terminal_recorded_at ON debuglet_cancellations
BEGIN SELECT RAISE(ABORT, 'terminal marker refused'); END`,
		"missing request": `CREATE TRIGGER refuse_terminal BEFORE UPDATE OF state ON debuglets
BEGIN DELETE FROM debuglet_cancellations WHERE debuglet_id=NEW.id; END`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newTGFixture(t, nil)
			run := f.seedDirect(t, tgFloorA)
			ssClaim(t, f, run)
			registryRegister(t, f.d, tgExecutorID)
			cleanupExec(t, f, trigger)
			if err := f.abort(t, run.id, "cancelled via API"); err == nil {
				t.Fatal("accepted cancellation without its durable decision")
			}
			tgAssertRow(t, f.row(t, run.id), models.RunStateUploaded, tgNull)
			tgAssertOrder(t, f, run, models.Outstanding)
			record, err := f.q.GetCancellation(f.ctx, run.row.ID)
			if err != nil || record.TerminalRecordedAt.Valid {
				t.Fatalf("failed terminal decision: %+v, %v", record, err)
			}
			cleanupExec(t, f, "DROP TRIGGER refuse_terminal")
			if err := f.abort(t, run.id, "cancelled via API"); err != nil {
				t.Fatal(err)
			}
			record, err = f.q.GetCancellation(f.ctx, run.row.ID)
			if err != nil || !record.TerminalRecordedAt.Valid || record.AcknowledgedAt.Valid {
				t.Fatalf("local terminal decision: %+v, %v", record, err)
			}
			tgAssertOrder(t, f, run, models.Refunded)
		})
	}
}

func TestCancellationAcknowledgementSurvivesLocalFailureAndRetry(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	run, err := f.submit(t, tgFloorA)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := f.submit(t, tgFloorB)
	if err != nil {
		t.Fatal(err)
	}
	drop := f.installTrigger(t)
	if err := f.abort(t, run.id, "first reason"); !errors.Is(err, ErrCancellationNotRecorded) {
		t.Fatalf("terminal failure: %v", err)
	}
	doc, err := f.d.Cancellation(f.ctx, run.id)
	if err != nil || doc.Disposition != "acknowledged" || doc.AcknowledgedAt == nil || doc.State != models.RunStateUploaded.String() {
		t.Fatalf("recorded ACK: %+v, %v", doc, err)
	}
	record, err := f.q.GetCancellation(f.ctx, run.row.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A racing refusal arriving after the ACK cannot erase it.
	if err := f.q.FailCancellation(f.ctx, database.FailCancellationParams{DebugletID: run.row.ID, Failure: "executor_refused"}); err != nil {
		t.Fatal(err)
	}
	if err := f.q.AttemptCancellation(f.ctx, database.AttemptCancellationParams{DebugletID: run.row.ID, AttemptedAt: sql.NullInt64{Int64: 1, Valid: true}}); err != nil {
		t.Fatal(err)
	}
	drop()
	if err := f.abort(t, run.id, "different retry reason"); err != nil {
		t.Fatal(err)
	}
	if len(peer.recordedAborts()) != 1 {
		t.Fatal("persisted ACK was delivered again")
	}
	got, err := f.q.GetCancellation(f.ctx, run.row.ID)
	if err != nil || got != record {
		t.Fatalf("first request/ACK changed: before=%+v after=%+v, %v", record, got, err)
	}
	tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgText("first reason"))
	tgAssertReserved(t, f, sibling, tgFloorB)
	before := f.snapshot(t)
	if _, err := f.d.Cancellation(f.ctx, run.id); err != nil {
		t.Fatal(err)
	}
	tgAssertSnapshot(t, f, before, "read-only cancellation inspection")
}

func TestCancellationTerminalAndWrongExecutorDoNotDeliver(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	run, err := f.submit(t, tgFloorA)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.AbortDebuglet(f.ctx, "another-executor", run.id, "foreign"); err == nil {
		t.Fatal("wrong executor accepted")
	}
	if _, err := f.q.GetCancellation(f.ctx, run.row.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign request recorded: %v", err)
	}
	if err := f.exit(t, run.id, 0, nil); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	if err := f.abort(t, run.id, "too late"); err != nil {
		t.Fatal(err)
	}
	doc, err := f.d.Cancellation(f.ctx, run.id)
	if err != nil || doc.Disposition != "not_needed" || doc.Reason != "already_terminal" || doc.AcknowledgedAt != nil || doc.AttemptedAt != nil {
		t.Fatalf("already terminal: %+v, %v", doc, err)
	}
	if len(peer.recordedAborts()) != 0 {
		t.Fatal("terminal run delivered another Abort")
	}
	tgAssertSnapshot(t, f, before, "already terminal cancellation")
}

// Losing the original binding after a failed delivery must not replace the
// specific failure that delivery recorded.
func TestUnboundCancellationKeepsEarlierDeliveryFailure(t *testing.T) {
	for _, tc := range []struct {
		failure string
		code    codes.Code
	}{
		{"executor_refused", codes.FailedPrecondition},
		{"transport_outcome_unknown", codes.Unavailable},
	} {
		t.Run(tc.failure, func(t *testing.T) {
			peer := &tgPeer{}
			f := newTGFixture(t, peer)
			run, err := f.submit(t, tgFloorA)
			if err != nil {
				t.Fatal(err)
			}
			peer.scriptAbort(status.Error(tc.code, "abort failed"))
			if err := f.abort(t, run.id, "first reason"); err == nil {
				t.Fatal("failed delivery was reported as success")
			}
			if doc, err := f.d.Cancellation(f.ctx, run.id); err != nil || doc.Disposition != "unresolved" || doc.Reason != tc.failure {
				t.Fatalf("delivery failure: %+v, %v", doc, err)
			}
			// A new session of the same executor makes the original binding unavailable.
			registryRegister(t, f.d, tgExecutorID)
			if err := f.abort(t, run.id, "second reason"); err != nil {
				t.Fatal(err)
			}
			tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgText("first reason"+unobservedCancellation))
			doc, err := f.d.Cancellation(f.ctx, run.id)
			if err != nil || doc.Disposition != "unresolved" || doc.Reason != tc.failure || doc.AttemptedAt == nil || doc.AcknowledgedAt != nil {
				t.Fatalf("unbound cancellation replaced the delivery failure: %+v, %v", doc, err)
			}
			if len(peer.recordedAborts()) != 1 {
				t.Fatalf("unbound cancellation delivered to a replacement: %d aborts", len(peer.recordedAborts()))
			}
		})
	}
}
