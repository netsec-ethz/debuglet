// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sqlite

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestArchivePreservesEvidenceAndReleasesOnlyQueueAdmission(t *testing.T) {
	db := newSchedulerTestDB(t)
	ctx := t.Context()
	limits := outputstore.DefaultLimits()
	limits.Runs = 1
	output, err := outputstore.New(db, limits)
	if err != nil {
		t.Fatal(err)
	}
	first, next := queuedSpec(), queuedSpec()
	first.OutputVersion = pb.OutputVersion
	charge, err := scheduler.StoredRunBytes(first)
	if err != nil {
		t.Fatal(err)
	}
	s := queueFixture(t, db, output, scheduler.QueueLimits{Runs: 1, Bytes: charge})
	if err := s.Insert(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Append(ctx, first.DebugletID, time.Now(), []byte("retained output")); err != nil {
		t.Fatal(err)
	}
	q := database.New(db)
	if err := s.RecordTerminal(ctx, scheduler.TerminalEvent{DebugletID: first.DebugletID, Binding: first.Binding, ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, next); !errors.Is(err, scheduler.ErrQueueLimit) {
		t.Fatalf("full queue: %v", err)
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	original, err := q.GetDebugletByUUID(ctx, first.DebugletID)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := q.GetDebugletExit(ctx, first.DebugletID.String())
	if err != nil {
		t.Fatal(err)
	}
	out, err := output.Get(ctx, first.DebugletID)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := output.Frames(ctx, first.DebugletID, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	used, err := q.GetOutputUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectArchive(ctx, db, first.DebugletID)
	if err != nil || inspected.ArchivedAt != nil {
		t.Fatalf("inspection=%+v %v", inspected, err)
	}
	archived, err := ArchiveRun(ctx, db, first.DebugletID, "incident-42")
	if err != nil || archived.ArchivedAt == nil || !archived.ExecutionRetained || !archived.TerminalRetained || !archived.OutputRetained {
		t.Fatalf("archive=%+v %v", archived, err)
	}
	again, err := ArchiveRun(ctx, db, first.DebugletID, "incident-42")
	if err != nil || !reflect.DeepEqual(archived, again) {
		t.Fatalf("idempotence=%+v %v", again, err)
	}
	if _, err := ArchiveRun(ctx, db, first.DebugletID, "another-decision"); err == nil {
		t.Fatal("changed an existing decision")
	}
	restarted := queueFixture(t, db, output, scheduler.QueueLimits{Runs: 1, Bytes: charge})
	// Even a hypothetical eligible binding cannot restore a locally archived run.
	restarted.eligibility = func(controlsession.Binding) bool { return true }
	if err := restarted.restore(ctx, func(scheduler.Spec) error { t.Fatal("archived run emitted for restoration"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Insert(ctx, first); err == nil {
		t.Fatal("archived run identity reused")
	}
	if err := restarted.Insert(ctx, next); err != nil {
		t.Fatalf("archive did not free the queue admission charge: %v", err)
	}
	if err := output.Admit(ctx, uuid.New(), first.Binding, pb.OutputVersion); !errors.Is(err, outputstore.ErrSpoolLimit) {
		t.Fatalf("archive released output capacity: %v", err)
	}
	if err := output.InterruptOpen(ctx); err != nil {
		t.Fatal(err)
	}
	if pending, err := output.Pending(ctx, "", 100); err != nil || len(pending) != 0 {
		t.Fatalf("archived output reconciled: %v %v", pending, err)
	}
	if pending, err := restarted.ListRetainedTerminals(ctx, first.Binding, 100); err != nil || len(pending) != 0 {
		t.Fatalf("archived terminal reconciled: %v %v", pending, err)
	}
	if _, err := q.GetOwnedDebugletByUUID(ctx, database.GetOwnedDebugletByUUIDParams{Uuid: first.DebugletID, DispatcherIncarnation: first.Binding.Incarnation, SessionID: first.Binding.SessionID}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("archived row remained mutable: %v", err)
	}
	if err := q.DeleteDebuglet(ctx, first.DebugletID); err != nil {
		t.Fatal(err)
	}
	if after, err := q.GetDebugletByUUID(ctx, first.DebugletID); err != nil || !reflect.DeepEqual(original, after) {
		t.Fatalf("execution evidence changed: %v", err)
	}
	if after, err := q.GetDebugletExit(ctx, first.DebugletID.String()); err != nil || !reflect.DeepEqual(terminal, after) {
		t.Fatalf("terminal evidence changed: %v", err)
	}
	if after, err := output.Get(ctx, first.DebugletID); err != nil || !reflect.DeepEqual(out, after) {
		t.Fatalf("output metadata changed: %v", err)
	}
	if after, err := output.Frames(ctx, first.DebugletID, 0, 64); err != nil || !reflect.DeepEqual(frames, after) {
		t.Fatalf("output frames changed: %v", err)
	}
	if after, err := q.GetOutputUsage(ctx); err != nil || after != used {
		t.Fatalf("output charge changed: %v", err)
	}
	found, err := restarted.InspectRetainedRun(ctx, first.DebugletID, controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()})
	if err != nil || found.Status != scheduler.RetainedRunFound || found.Binding != first.Binding {
		t.Fatalf("ordinary retained inspection lost evidence: %+v %v", found, err)
	}
}

func TestArchiveRefusesInvalidAndFailedDecisions(t *testing.T) {
	db := newSchedulerTestDB(t)
	ctx := t.Context()
	spec := queuedSpec()
	s := queueFixture(t, db, nil, scheduler.QueueLimits{Runs: 1, Bytes: 1 << 20})
	if err := s.Insert(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"", " leading", "line\nbreak"} {
		if _, err := ArchiveRun(ctx, db, spec.DebugletID, reason); err == nil {
			t.Fatalf("accepted reason %q", reason)
		}
	}
	if _, err := ArchiveRun(ctx, db, uuid.New(), "missing"); err == nil {
		t.Fatal("archived absent run")
	}
	if _, err := db.Exec("CREATE TRIGGER refuse_archive BEFORE INSERT ON operator_dispositions BEGIN SELECT RAISE(ABORT,'disk refusal'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := ArchiveRun(ctx, db, spec.DebugletID, "incident-1"); err == nil {
		t.Fatal("failed write accepted")
	}
	if r, err := InspectArchive(ctx, db, spec.DebugletID); err != nil || r.ArchivedAt != nil {
		t.Fatalf("failure changed decision: %+v %v", r, err)
	}
	restarted := queueFixture(t, db, nil, scheduler.QueueLimits{Runs: 1, Bytes: 1 << 20})
	if err := restarted.Insert(ctx, queuedSpec()); !errors.Is(err, scheduler.ErrQueueLimit) {
		t.Fatalf("failed archive released charge: %v", err)
	}
}

func TestArchiveTerminalOnlyCannotReuseIdentity(t *testing.T) {
	db := newSchedulerTestDB(t)
	ctx := t.Context()
	s := queueFixture(t, db, nil, scheduler.DefaultQueueLimits())
	spec := queuedSpec()
	if err := s.RecordTerminal(ctx, scheduler.TerminalEvent{DebugletID: spec.DebugletID, Binding: spec.Binding, ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := ArchiveRun(ctx, db, spec.DebugletID, "terminal-incident")
	if err != nil || r.ExecutionRetained || !r.TerminalRetained || r.ArchivedAt == nil {
		t.Fatalf("terminal-only=%+v %v", r, err)
	}
	restarted := queueFixture(t, db, nil, scheduler.DefaultQueueLimits())
	if err := restarted.Insert(ctx, spec); err == nil {
		t.Fatal("terminal-only archived identity reused")
	}
}
