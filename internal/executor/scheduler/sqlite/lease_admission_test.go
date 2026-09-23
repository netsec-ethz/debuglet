package sqlite

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

func admissionPass(_ controlsession.Binding, commit func()) error { commit(); return nil }

func admissionShutdown(t *testing.T, storage *SqliteStorage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := storage.Shutdown(ctx); err != nil {
		t.Errorf("admission fixture shutdown: %v", err)
	}
}

func TestSQLiteStrictAdmissionRequiresBothGuards(t *testing.T) {
	// A nil DB is deliberate: constructor refusal must precede database access.
	for _, a := range []scheduler.Admission{{}, {Insert: admissionPass}, {Start: admissionPass}} {
		if s, err := NewStorage(nil, storageTestEligibility, a); err == nil || s != nil {
			t.Fatalf("incomplete strict admission accepted: storage=%v error=%v", s, err)
		}
	}
}

func TestSQLiteLeaseRefusalPrecedesPersistence(t *testing.T) {
	db := newSchedulerTestDB(t)
	refused := errors.New("lease admission refused")
	var guards atomic.Int32
	storage, err := NewStorage(db, storageTestEligibility, scheduler.Admission{
		Insert: func(binding controlsession.Binding, _ func()) error {
			guards.Add(1)
			if binding != storageTestBinding() {
				t.Error("guard received wrong binding")
			}
			return refused
		}, Start: admissionPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admissionShutdown(t, storage) })
	observed := &insertObservedDB{}
	storage.decorate = observed.decorate
	spec := insertTestSpec()
	if err := storage.Insert(context.Background(), spec); !errors.Is(err, refused) {
		t.Fatalf("lease refusal lost: %v", err)
	}
	if guards.Load() != 1 || observed.calls.Load() != 0 {
		t.Fatalf("guard=%d SQL=%d", guards.Load(), observed.calls.Load())
	}
	insertAssertRows(t, db)
	insertAssertNotQueued(t, storage, spec.DebugletID)
}

func TestSQLiteLeaseExpiryAfterPersistenceRetainsAcceptedRow(t *testing.T) {
	db := newSchedulerTestDB(t)
	refused := errors.New("lease expired before dispatch")
	var live atomic.Bool
	live.Store(true)
	guard := func(_ controlsession.Binding, commit func()) error {
		if !live.Load() {
			return refused
		}
		commit()
		return nil
	}
	storage, err := NewStorage(db, storageTestEligibility, scheduler.Admission{Insert: guard, Start: guard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admissionShutdown(t, storage) })
	observed := &insertObservedDB{afterSuccess: func() { live.Store(false) }}
	storage.decorate = observed.decorate
	var starts, failures atomic.Int32
	storage.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
		starts.Add(1)
		return scheduler.Completion{}
	})
	storage.RegisterFailed(func(context.Context, scheduler.Spec, error) scheduler.Completion {
		failures.Add(1)
		return scheduler.Completion{}
	})
	spec := insertTestSpec()
	if err := storage.Insert(context.Background(), spec); err != nil {
		t.Fatalf("persisted reservation falsely rejected after expiry: %v", err)
	}
	insertAssertRows(t, db, spec)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := storage.StartLoop(ctx); !errors.Is(err, refused) {
		t.Errorf("expired start admission returned %v", err)
	}
	admissionShutdown(t, storage)
	if starts.Load() != 0 || failures.Load() != 0 || observed.calls.Load() != 1 {
		t.Fatalf("expired queued work caused effects: starts=%d failed=%d SQL=%d", starts.Load(), failures.Load(), observed.calls.Load())
	}
	insertAssertRows(t, db, spec)
}

func TestSQLiteCancelledInsideAdmissionHasNoReservation(t *testing.T) {
	db := newSchedulerTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	storage, err := NewStorage(db, storageTestEligibility, scheduler.Admission{
		Insert: func(_ controlsession.Binding, commit func()) error { cancel(); commit(); return nil }, Start: admissionPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admissionShutdown(t, storage) })
	observed := &insertObservedDB{}
	storage.decorate = observed.decorate
	spec := insertTestSpec()
	if err := storage.Insert(ctx, spec); !errors.Is(err, context.Canceled) {
		t.Fatalf("commit did not recheck cancellation: %v", err)
	}
	if observed.calls.Load() != 0 {
		t.Fatalf("cancelled reservation entered SQL %d times", observed.calls.Load())
	}
	insertAssertRows(t, db)
	insertAssertNotQueued(t, storage, spec.DebugletID)
}

func TestSQLiteReservedWriteSurvivesLeaseLossAndShutdown(t *testing.T) {
	db := newSchedulerTestDB(t)
	var live atomic.Bool
	live.Store(true)
	refused := errors.New("lease unavailable")
	guard := func(_ controlsession.Binding, commit func()) error {
		if !live.Load() {
			return refused
		}
		commit()
		return nil
	}
	storage, err := NewStorage(db, storageTestEligibility, scheduler.Admission{Insert: guard, Start: guard})
	if err != nil {
		t.Fatal(err)
	}
	persisted, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	storage.decorate = (&insertObservedDB{afterSuccess: func() { close(persisted); <-release }}).decorate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var insertErr error
	go func() { defer close(done); insertErr = storage.Insert(ctx, insertTestSpec()) }()
	joined := false
	join := func() bool {
		select {
		case <-done:
			joined = true
			return true
		case <-time.After(6 * time.Second):
			t.Error("accepted Insert caller did not join")
			return false
		}
	}
	t.Cleanup(func() {
		unlock()
		cancel()
		if !joined {
			join()
		}
		admissionShutdown(t, storage)
	})
	select {
	case <-persisted:
	case <-ctx.Done():
		t.Fatal("successful real INSERT was not reached")
	}
	live.Store(false)
	short, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = storage.Shutdown(short)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("shutdown passed held accepted write: %v", err)
	}
	select {
	case <-done:
		t.Error("Insert returned before actual write wrapper joined")
	default:
	}
	unlock()
	if !join() {
		return
	}
	if insertErr != nil {
		t.Fatalf("reserved successful write rejected: %v", insertErr)
	}
	admissionShutdown(t, storage)
	insertAssertRows(t, db, insertTestSpec())
}
