// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package outputstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func fixture(t *testing.T, limits Limits) (*Store, *sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "output.sqlite")
	db, err := sqlitedb.Open(path, sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	s, err := New(db, limits)
	if err != nil {
		t.Fatal(err)
	}
	return s, db, path
}

func admit(t *testing.T, s *Store) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := s.Admit(t.Context(), id, controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}, pb.OutputVersion); err != nil {
		t.Fatal(err)
	}
	return id
}

func appendFrame(t *testing.T, s *Store, id uuid.UUID, data string) Frame {
	t.Helper()
	f, err := s.Append(t.Context(), id, time.Unix(1700000000, 123456789), []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSpoolRestartAcknowledgementAndIndependentLifetime(t *testing.T) {
	s, db, path := fixture(t, DefaultLimits())
	ctx := t.Context()
	id := admit(t, s)
	first := appendFrame(t, s, id, "first")
	appendFrame(t, s, id, "second")
	// The independent spool has no scheduler foreign key and survives its deletion.
	if _, err := db.ExecContext(ctx, `DELETE FROM debuglets`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s, err = New(reopened, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var synchronous int
	if err := reopened.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous == 0 {
		t.Fatalf("sync=%d err=%v", synchronous, err)
	}
	frames, err := s.Frames(ctx, id, 0, 64)
	if err != nil || len(frames) != 2 || frames[0].Sequence != 1 || !frames[0].Timestamp.Equal(first.Timestamp) || string(frames[0].Output) != "first" {
		t.Fatalf("frames=%+v err=%v", frames, err)
	}
	if err := s.Acknowledge(ctx, id, 3, nil); !errors.Is(err, ErrAcknowledgement) {
		t.Fatalf("future ACK=%v", err)
	}
	for range 2 {
		if err := s.Acknowledge(ctx, id, 1, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.InterruptOpen(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := s.Get(ctx, id)
	if err != nil || r.End == nil || r.End.LastSequence != 2 || r.End.Reason != pb.OutputReasonExecutorInterrupted || r.EmittedBytes != 11 || r.QueuedBytes != 6 {
		t.Fatalf("run=%+v err=%v", r, err)
	}
	if _, err := s.Append(ctx, id, time.Now(), []byte("late")); !errors.Is(err, ErrFinalized) {
		t.Fatalf("late append=%v", err)
	}
	if _, err := s.Finish(ctx, id, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, ""); !errors.Is(err, ErrFinalized) {
		t.Fatalf("conflicting end=%v", err)
	}
	for range 2 {
		if err := s.Acknowledge(ctx, id, 2, r.End); err != nil {
			t.Fatal(err)
		}
	}
	frames, err = s.Frames(ctx, id, 0, 64)
	if err != nil || len(frames) != 0 {
		t.Fatalf("acknowledged frames=%v %v", frames, err)
	}
	used, err := database.New(reopened).GetOutputUsage(ctx)
	if err != nil || used != pb.OutputRunCharge {
		t.Fatalf("usage=%d %v", used, err)
	}
	pending, err := s.Pending(ctx, "", 100)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending=%v %v", pending, err)
	}
	if err := s.Admit(ctx, id, r.Binding, pb.OutputVersion); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit(ctx, id, controlsession.Binding{Incarnation: uuid.NewString(), SessionID: r.Binding.SessionID}, pb.OutputVersion); !errors.Is(err, ErrIdentity) {
		t.Fatalf("new binding=%v", err)
	}
}

func TestSpoolLimitsDoNotResetAfterAcknowledgement(t *testing.T) {
	limits := DefaultLimits()
	limits.RunBytes = 3
	limits.RunFrames = 2
	limits.Runs = 1
	s, _, _ := fixture(t, limits)
	ctx := t.Context()
	id := admit(t, s)
	appendFrame(t, s, id, "ab")
	if err := s.Acknowledge(ctx, id, 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, id, time.Now(), []byte("cd")); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("emitted quota reset: %v", err)
	}
	appendFrame(t, s, id, "c")
	if err := s.Acknowledge(ctx, id, 2, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, id, time.Now(), []byte("d")); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("frame quota reset: %v", err)
	}
	if _, err := s.Append(ctx, id, time.Now(), nil); err == nil {
		t.Fatal("empty frame accepted")
	}
	if _, err := s.Append(ctx, id, time.Now(), make([]byte, pb.MaxOutputFrameBytes+1)); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if err := s.Admit(ctx, uuid.New(), controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}, pb.OutputVersion); !errors.Is(err, ErrSpoolLimit) {
		t.Fatalf("run cap=%v", err)
	}
}

func TestSpoolQuotaIncludesTinyFramesAndConcurrentWriters(t *testing.T) {
	limits := DefaultLimits()
	limits.NodeBytes = 2*pb.OutputRunCharge + pb.OutputFrameCharge + 1
	s, db, _ := fixture(t, limits)
	ctx := t.Context()
	ids := []uuid.UUID{admit(t, s), admit(t, s)}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range ids {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Append(ctx, id, time.Now(), []byte("x")); results <- err }()
	}
	wg.Wait()
	close(results)
	ok, full := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrSpoolLimit) {
			full++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || full != 1 {
		t.Fatalf("success=%d full=%d", ok, full)
	}
	used, err := database.New(db).GetOutputUsage(ctx)
	if err != nil || used != limits.NodeBytes {
		t.Fatalf("usage=%d err=%v", used, err)
	}
}

func TestSpoolFailedWriteRollsBackSequenceAndUsage(t *testing.T) {
	s, db, _ := fixture(t, DefaultLimits())
	ctx := t.Context()
	id := admit(t, s)
	var pages int
	if err := db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, id, time.Now(), bytes.Repeat([]byte("x"), pb.MaxOutputFrameBytes)); err == nil {
		t.Fatal("expected SQLITE_FULL")
	}
	r, err := s.Get(ctx, id)
	if err != nil || r.LastSequence != 0 || r.EmittedBytes != 0 || r.QueuedBytes != 0 || r.End != nil {
		t.Fatalf("failed write changed prefix=%+v %v", r, err)
	}
	used, err := database.New(db).GetOutputUsage(ctx)
	if err != nil || used != pb.OutputRunCharge {
		t.Fatalf("failed write charged=%d %v", used, err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA max_page_count=10000"); err != nil {
		t.Fatal(err)
	}
	f := appendFrame(t, s, id, "recovered")
	if f.Sequence != 1 {
		t.Fatalf("sequence=%d", f.Sequence)
	}
}

func TestSpoolQuotaReceiptPreservesProducerEnd(t *testing.T) {
	s, db, path := fixture(t, DefaultLimits())
	ctx := t.Context()
	id := admit(t, s)
	appendFrame(t, s, id, "accepted")
	appendFrame(t, s, id, "rejected")
	receipt := &pb.DebugletOutputEnd{LastSequence: 1, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, Reason: pb.OutputReasonStorageLimit}
	if err := s.AcceptTruncation(ctx, id, receipt); !errors.Is(err, ErrAcknowledgement) {
		t.Fatalf("unjoined producer receipt=%v", err)
	}
	end, err := s.Finish(ctx, id, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Acknowledge(ctx, id, 1, receipt); !errors.Is(err, ErrAcknowledgement) {
		t.Fatalf("ordinary ACK overwrote producer end: %v", err)
	}
	for range 2 {
		if err := s.AcceptTruncation(ctx, id, receipt); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s, err = New(reopened, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Get(ctx, id)
	if err != nil || !sameEnd(r.End, end) || !sameEnd(r.Receipt, receipt) || !r.EndAcknowledged || r.QueuedBytes != 0 || r.AcknowledgedSequence != 1 {
		t.Fatalf("receipt state=%+v err=%v", r, err)
	}
	conflict := &pb.DebugletOutputEnd{LastSequence: 0, Status: receipt.Status, Reason: receipt.Reason}
	if err := s.AcceptTruncation(ctx, id, conflict); !errors.Is(err, ErrAcknowledgement) {
		t.Fatalf("conflicting receipt=%v", err)
	}
	used, err := database.New(reopened).GetOutputUsage(ctx)
	if err != nil || used != pb.OutputRunCharge {
		t.Fatalf("receipt charge=%d %v", used, err)
	}
}

func TestSpoolEmptyEndAndCanceledAdmission(t *testing.T) {
	s, _, _ := fixture(t, DefaultLimits())
	ctx := t.Context()
	id := admit(t, s)
	end, err := s.Finish(ctx, id, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, "")
	if err != nil || end.LastSequence != 0 {
		t.Fatalf("end=%v err=%v", end, err)
	}
	if err := s.Acknowledge(ctx, id, 0, end); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	other := uuid.New()
	if err := s.Admit(canceled, other, controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}, pb.OutputVersion); err == nil {
		t.Fatal("canceled admission succeeded")
	}
	if _, err := s.Get(ctx, other); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("canceled admission persisted: %v", err)
	}
}
