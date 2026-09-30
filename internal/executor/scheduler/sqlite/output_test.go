// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func outputFixture(t *testing.T, limits outputstore.Limits) (*SqliteStorage, *outputstore.Store, *sql.DB) {
	t.Helper()
	db := newSchedulerTestDB(t)
	output, err := outputstore.New(db, limits)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStorage(db, output, storageTestEligibility, scheduler.Admission{Insert: admissionPass, Start: admissionPass}, scheduler.DefaultQueueLimits())
	if err != nil {
		t.Fatal(err)
	}
	cancellationCleanup(t, s)
	return s, output, db
}

func outputSpec() scheduler.Spec {
	spec := insertTestSpec()
	spec.DebugletID = uuid.New()
	spec.OutputVersion = pb.OutputVersion
	future := time.Now().Add(time.Hour)
	spec.StartTime = &future
	return spec
}

func TestQueuedOutputAdmissionCancellationAndQuotaAreAtomic(t *testing.T) {
	limits := outputstore.DefaultLimits()
	limits.Runs = 1
	s, output, db := outputFixture(t, limits)
	ctx := t.Context()
	spec := outputSpec()
	if err := s.Insert(ctx, spec); err != nil {
		t.Fatal(err)
	}
	row, err := output.Get(ctx, spec.DebugletID)
	if err != nil || row.End != nil || row.Binding != spec.Binding {
		t.Fatalf("admitted output=%+v err=%v", row, err)
	}
	wrong := spec.Binding
	wrong.SessionID = uuid.NewString()
	if found, err := s.CancelBound(ctx, spec.DebugletID, wrong, nil); found || !errors.Is(err, scheduler.ErrBindingMismatch) {
		t.Fatalf("wrong owner=%t %v", found, err)
	}
	second := outputSpec()
	if err := s.Insert(ctx, second); !errors.Is(err, outputstore.ErrSpoolLimit) {
		t.Fatalf("quota refusal=%v", err)
	}
	if _, err := database.New(db).GetDebugletByUUID(ctx, second.DebugletID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("refused scheduler row survived: %v", err)
	}
	if _, err := output.Get(ctx, second.DebugletID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("refused output row survived: %v", err)
	}
	if found, err := s.CancelBound(ctx, spec.DebugletID, spec.Binding, context.Canceled); !found || err != nil {
		t.Fatalf("cancel=%t %v", found, err)
	}
	row, err = output.Get(ctx, spec.DebugletID)
	if err != nil || row.End == nil || row.End.LastSequence != 0 || row.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE {
		t.Fatalf("queued end=%+v err=%v", row, err)
	}
	if _, err := database.New(db).GetDebugletByUUID(ctx, spec.DebugletID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("canceled execution persisted: %v", err)
	}
	if found, err := s.CancelBound(ctx, spec.DebugletID, spec.Binding, nil); found || err != nil {
		t.Fatalf("cancel retry=%t %v", found, err)
	}
	usage, err := database.New(db).GetOutputUsage(ctx)
	if err != nil || usage != pb.OutputRunCharge {
		t.Fatalf("usage=%d %v", usage, err)
	}
}

func TestQueuedOutputFinalizerOutlivesCallerDeadline(t *testing.T) {
	s, output, db := outputFixture(t, outputstore.DefaultLimits())
	ctx := t.Context()
	spec := outputSpec()
	if err := s.Insert(ctx, spec); err != nil {
		t.Fatal(err)
	}
	held, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	before := db.Stats().WaitCount
	bounded, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	done := cancellationCaller(t, func() { held.Close() }, func() cancellationResult {
		found, err := s.CancelBound(bounded, spec.DebugletID, spec.Binding, nil)
		return cancellationResult{found, err}
	})
	awaitPoolWaiters(t, db, before+1)
	result := cancellationAwait(t, done, "caller deadline")
	if !result.found || !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("deadline=%+v", result)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	// This retry either joins the detached owner or observes its committed absence.
	if _, err := s.CancelBound(ctx, spec.DebugletID, spec.Binding, nil); err != nil {
		t.Fatal(err)
	}
	row, err := output.Get(ctx, spec.DebugletID)
	if err != nil || row.End == nil || row.End.LastSequence != 0 || row.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE {
		t.Fatalf("detached end=%+v %v", row, err)
	}
	if _, err := database.New(db).GetDebugletByUUID(ctx, spec.DebugletID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("detached deletion=%v", err)
	}
}

func TestQueuedOutputDeleteFailureRollsBackFinality(t *testing.T) {
	s, output, db := outputFixture(t, outputstore.DefaultLimits())
	ctx := t.Context()
	spec := outputSpec()
	if err := s.Insert(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER refuse_delete BEFORE DELETE ON debuglets BEGIN SELECT RAISE(ABORT,'delete refused'); END`); err != nil {
		t.Fatal(err)
	}
	if found, err := s.CancelBound(ctx, spec.DebugletID, spec.Binding, nil); !found || err == nil {
		t.Fatalf("failed deletion=%t %v", found, err)
	}
	row, err := output.Get(ctx, spec.DebugletID)
	if err != nil || row.End != nil {
		t.Fatalf("uncommitted end survived=%+v %v", row, err)
	}
	if _, err := database.New(db).GetDebugletByUUID(ctx, spec.DebugletID); err != nil {
		t.Fatal("failed deletion lost execution", err)
	}
	if _, err := db.ExecContext(ctx, `DROP TRIGGER refuse_delete`); err != nil {
		t.Fatal(err)
	}
	if found, err := s.CancelBound(ctx, spec.DebugletID, spec.Binding, nil); !found || err != nil {
		t.Fatalf("retry=%t %v", found, err)
	}
	row, err = output.Get(ctx, spec.DebugletID)
	if err != nil || row.End == nil {
		t.Fatalf("retry end=%+v %v", row, err)
	}
}

func TestOutputFinalizerPreservesStartedProducerAndExistingEnds(t *testing.T) {
	s, output, db := outputFixture(t, outputstore.DefaultLimits())
	ctx := t.Context()
	spec := outputSpec()
	spec.StartTime = nil
	started, canceled, release := make(chan struct{}), make(chan struct{}), newCancellationGate(t)
	s.RegisterOnStart(func(runCtx context.Context, spec scheduler.Spec) scheduler.Completion {
		_, err := output.Append(ctx, spec.DebugletID, time.Now(), []byte("accepted"))
		if err != nil {
			return scheduler.Completion{CleanupErr: err}
		}
		close(started)
		<-runCtx.Done()
		close(canceled)
		release.hold(context.Background())
		_, err = output.Finish(ctx, spec.DebugletID, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, "")
		return scheduler.Completion{CleanupErr: err}
	})
	if err := s.Insert(ctx, spec); err != nil {
		t.Fatal(err)
	}
	cancellationLoop(t, s)
	cancellationAwait(t, started, "started producer")
	done := cancellationCaller(t, release.open, func() cancellationResult {
		found, err := s.CancelBound(ctx, spec.DebugletID, spec.Binding, nil)
		return cancellationResult{found, err}
	})
	cancellationAwait(t, canceled, "running cancellation")
	row, err := output.Get(ctx, spec.DebugletID)
	if err != nil || row.End != nil || row.LastSequence != 1 {
		t.Fatalf("unjoined producer finalized=%+v %v", row, err)
	}
	identity, err := database.New(db).GetDebugletIdentity(ctx, spec.DebugletID)
	if err != nil || identity.StartedAt.IsZero() {
		t.Fatalf("producer marker=%+v %v", identity, err)
	}
	cancellationStillWaiting(t, done, "running cancel")
	release.open()
	result := cancellationAwait(t, done, "producer joined")
	if !result.found || result.err != nil {
		t.Fatalf("cancel=%+v", result)
	}
	row, err = output.Get(ctx, spec.DebugletID)
	if err != nil || row.End == nil || row.End.LastSequence != 1 || row.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE {
		t.Fatalf("producer prefix changed=%+v %v", row, err)
	}
}

func TestQueuedOutputPreservesLegacyAndRetainedPrefix(t *testing.T) {
	for _, which := range []string{"legacy", "prefix", "end"} {
		t.Run(which, func(t *testing.T) {
			s, output, _ := outputFixture(t, outputstore.DefaultLimits())
			ctx := t.Context()
			spec := outputSpec()
			if which == "legacy" {
				spec.OutputVersion = 0
			}
			if err := s.Insert(ctx, spec); err != nil {
				t.Fatal(err)
			}
			if which == "prefix" {
				if _, err := output.Append(ctx, spec.DebugletID, time.Now(), []byte("retained")); err != nil {
					t.Fatal(err)
				}
			}
			if which == "end" {
				if _, err := output.Finish(ctx, spec.DebugletID, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, pb.OutputReasonExecutorInterrupted); err != nil {
					t.Fatal(err)
				}
			}
			if found, err := s.CancelBound(ctx, spec.DebugletID, spec.Binding, nil); !found || err != nil {
				t.Fatalf("cancel=%t %v", found, err)
			}
			row, err := output.Get(ctx, spec.DebugletID)
			switch which {
			case "legacy":
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("invented legacy output=%+v %v", row, err)
				}
			case "prefix":
				if err != nil || row.End != nil || row.LastSequence != 1 {
					t.Fatalf("prefix changed=%+v %v", row, err)
				}
			case "end":
				if err != nil || row.End == nil || row.End.Reason != pb.OutputReasonExecutorInterrupted {
					t.Fatalf("end changed=%+v %v", row, err)
				}
			}
		})
	}
}

func TestQueuedOutputFinalizerCrashBoundary(t *testing.T) {
	if path := os.Getenv("DEBUGLET_OUTPUT_CANCEL_CHILD_DB"); path != "" {
		db, err := sqlitedb.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		output, err := outputstore.New(db, outputstore.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewStorage(db, output, storageTestEligibility, scheduler.Admission{Insert: admissionPass, Start: admissionPass}, scheduler.DefaultQueueLimits())
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(os.Getenv("DEBUGLET_OUTPUT_CANCEL_CHILD_ID"))
		if os.Getenv("DEBUGLET_OUTPUT_CANCEL_CHILD_PHASE") == "before_commit" {
			s.decorate = (&cancellationDB{beforeDelete: func(context.Context) { os.Exit(23) }}).decorate
		}
		if err := s.finalize(t.Context(), id); err != nil {
			t.Fatal(err)
		}
		os.Exit(24)
	}
	for _, phase := range []string{"before_commit", "after_commit"} {
		t.Run(phase, func(t *testing.T) {
			s, _, db := outputFixture(t, outputstore.DefaultLimits())
			ctx := t.Context()
			spec := outputSpec()
			if err := s.Insert(ctx, spec); err != nil {
				t.Fatal(err)
			}
			if err := s.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			var number int
			var name, path string
			if err := db.QueryRowContext(ctx, "PRAGMA database_list").Scan(&number, &name, &path); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQueuedOutputFinalizerCrashBoundary$")
			command.Env = append(os.Environ(), "DEBUGLET_OUTPUT_CANCEL_CHILD_DB="+path, "DEBUGLET_OUTPUT_CANCEL_CHILD_ID="+spec.DebugletID.String(), "DEBUGLET_OUTPUT_CANCEL_CHILD_PHASE="+phase)
			data, err := command.CombinedOutput()
			var exit *exec.ExitError
			want := 24
			if phase == "before_commit" {
				want = 23
			}
			if !errors.As(err, &exit) || exit.ExitCode() != want {
				t.Fatalf("child exit=%v output=%s", err, data)
			}
			reopened, err := sqlitedb.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			output, err := outputstore.New(reopened, outputstore.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			row, err := output.Get(ctx, spec.DebugletID)
			if err != nil {
				t.Fatal(err)
			}
			_, executionErr := database.New(reopened).GetDebugletByUUID(ctx, spec.DebugletID)
			if phase == "before_commit" {
				if row.End != nil || executionErr != nil {
					t.Fatalf("partial cancellation committed: %+v %v", row, executionErr)
				}
			} else if row.End == nil || row.End.LastSequence != 0 || row.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE || !errors.Is(executionErr, sql.ErrNoRows) {
				t.Fatalf("atomic cancellation lost: %+v %v", row, executionErr)
			}
			if err := output.InterruptOpen(ctx); err != nil {
				t.Fatal(err)
			}
			after, err := output.Get(ctx, spec.DebugletID)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "before_commit" && after.End.Reason != pb.OutputReasonExecutorInterrupted {
				t.Fatalf("restart invented completion: %+v", after)
			}
			if phase == "after_commit" && after.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE {
				t.Fatalf("restart rewrote cancellation: %+v", after)
			}
		})
	}
}
