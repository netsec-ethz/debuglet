// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func queueFixture(t *testing.T, db *sql.DB, output *outputstore.Store, limits scheduler.QueueLimits) *SqliteStorage {
	t.Helper()
	s, err := NewStorage(db, output, storageTestEligibility, scheduler.Admission{Insert: admissionPass, Start: admissionPass}, limits)
	if err != nil {
		t.Fatal(err)
	}
	cancellationCleanup(t, s)
	return s
}

func queuedSpec() scheduler.Spec {
	s := insertTestSpec()
	s.DebugletID = uuid.New()
	future := time.Now().Add(time.Hour)
	s.StartTime = &future
	return s
}

func TestQueuedBytesAreDurableAndReleasedOnlyAfterDeletion(t *testing.T) {
	db := newSchedulerTestDB(t)
	first, second, third := queuedSpec(), queuedSpec(), queuedSpec()
	charge, err := scheduler.StoredRunBytes(first)
	if err != nil {
		t.Fatal(err)
	}
	s := queueFixture(t, db, nil, scheduler.QueueLimits{Runs: 10, Bytes: charge * 2})
	for _, spec := range []scheduler.Spec{first, second} {
		if err := s.Insert(t.Context(), spec); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Insert(t.Context(), third); !errors.Is(err, scheduler.ErrQueueLimit) {
		t.Fatalf("byte quota=%v", err)
	}
	if _, err := database.New(db).GetDebugletByUUID(t.Context(), third.DebugletID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("refused row persisted: %v", err)
	}
	// A failed retirement retains both the row and its charge.
	if _, err := db.Exec("CREATE TRIGGER hold_queue BEFORE DELETE ON debuglets BEGIN SELECT RAISE(ABORT,'retained'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CancelBound(t.Context(), first.DebugletID, first.Binding, nil); err == nil {
		t.Fatal("delete unexpectedly succeeded")
	}
	if err := s.Insert(t.Context(), third); !errors.Is(err, scheduler.ErrQueueLimit) {
		t.Fatalf("failed delete released charge: %v", err)
	}
	if _, err := db.Exec("DROP TRIGGER hold_queue"); err != nil {
		t.Fatal(err)
	}
	if found, err := s.CancelBound(t.Context(), first.DebugletID, first.Binding, nil); !found || err != nil {
		t.Fatalf("retirement=%t %v", found, err)
	}
	if _, err := s.CancelBound(t.Context(), first.DebugletID, first.Binding, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(t.Context(), third); err != nil {
		t.Fatal(err)
	}
	insertAssertRows(t, db, second, third)
}

func TestQueuedRowQuotaIncludesRestartAndQuarantine(t *testing.T) {
	db := newSchedulerTestDB(t)
	first := queuedSpec()
	s := queueFixture(t, db, nil, scheduler.QueueLimits{Runs: 1, Bytes: 1 << 20})
	if err := s.Insert(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(t.Context(), first); err == nil || errors.Is(err, scheduler.ErrQueueLimit) {
		t.Fatalf("duplicate owner changed to quota refusal: %v", err)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStorage(db, nil, func(controlsession.Binding) bool { return false }, scheduler.Admission{Insert: admissionPass, Start: admissionPass}, scheduler.QueueLimits{Runs: 1, Bytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	cancellationCleanup(t, restarted)
	if err := restarted.RestoreFromDatabase(t.Context()); err != nil {
		t.Fatal(err)
	}
	if restarted.QuarantinedCount() != 1 {
		t.Fatal("old row was not quarantined")
	}
	if err := restarted.Insert(t.Context(), queuedSpec()); !errors.Is(err, scheduler.ErrQueueLimit) {
		t.Fatalf("quarantine lost charge: %v", err)
	}
	if err := restarted.Insert(t.Context(), first); err == nil || errors.Is(err, scheduler.ErrQueueLimit) {
		t.Fatalf("existing identity became quota refusal: %v", err)
	}
	insertAssertRows(t, db, first)
}

func TestQueuedAdmissionIsAtomicAcrossStorageInstances(t *testing.T) {
	db := newSchedulerTestDB(t)
	db.SetMaxOpenConns(2)
	limits := scheduler.QueueLimits{Runs: 1, Bytes: 1 << 20}
	stores := []*SqliteStorage{queueFixture(t, db, nil, limits), queueFixture(t, db, nil, limits)}
	ready := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, s := range stores {
		wg.Add(1)
		go func(s *SqliteStorage) { defer wg.Done(); <-ready; results <- s.Insert(t.Context(), queuedSpec()) }(s)
	}
	close(ready)
	wg.Wait()
	close(results)
	accepted, refused := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, scheduler.ErrQueueLimit) {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || refused != 1 {
		t.Fatalf("accepted=%d refused=%d", accepted, refused)
	}
}

func TestQueuedOutputFailureRollsBackItsQueueCharge(t *testing.T) {
	db := newSchedulerTestDB(t)
	limits := outputstore.DefaultLimits()
	limits.Runs = 1
	output, err := outputstore.New(db, limits)
	if err != nil {
		t.Fatal(err)
	}
	s := queueFixture(t, db, output, scheduler.QueueLimits{Runs: 2, Bytes: 1 << 20})
	first, second := queuedSpec(), queuedSpec()
	first.OutputVersion = pb.OutputVersion
	second.OutputVersion = pb.OutputVersion
	if err := s.Insert(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(t.Context(), second); !errors.Is(err, outputstore.ErrSpoolLimit) {
		t.Fatalf("output quota=%v", err)
	}
	// A legacy-output run proves the failed transaction consumed no queue slot.
	third := queuedSpec()
	if err := s.Insert(t.Context(), third); err != nil {
		t.Fatal(err)
	}
	insertAssertRows(t, db, first, third)
}

func TestQueuedAdmissionRejectsModuleBeforeSQL(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := queueFixture(t, db, nil, scheduler.DefaultQueueLimits())
	observed := &insertObservedDB{}
	s.decorate = observed.decorate
	spec := queuedSpec()
	spec.Wasm = make([]byte, scheduler.MaxModuleBytes+1)
	if err := s.Insert(context.Background(), spec); !errors.Is(err, scheduler.ErrUploadLimit) {
		t.Fatalf("module bound=%v", err)
	}
	if observed.calls.Load() != 0 {
		t.Fatal("oversized module reached SQL")
	}
}
