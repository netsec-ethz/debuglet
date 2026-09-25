package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

const retentionTestBound = 10 * time.Second

func retentionOtherBinding() controlsession.Binding {
	return controlsession.Binding{Incarnation: "c31f0dc2-3f96-4a5a-aa2a-a4bcc16d88fb", SessionID: "0f3b31ce-2d0b-4d5f-9df3-5a2d9b1c6a11"}
}

func retentionEvent(id uuid.UUID, code int32, message string) scheduler.TerminalEvent {
	event := scheduler.TerminalEvent{
		DebugletID: id, Binding: storageTestBinding(), ExitCode: code,
		RecordedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	if message != "" {
		event.ErrorMessage = &message
	}
	return event
}

// The terminal result outlives the execution row it describes: finalization
// deletes the run, and the retained event still says what the executor chose
// and how far its delivery got.
func TestTerminalEventOutlivesItsRun(t *testing.T) {
	db := newSchedulerTestDB(t)
	storage := newTestStorage(t, db, storageTestEligibility)
	ctx, cancel := context.WithTimeout(context.Background(), retentionTestBound)
	defer cancel()

	spec := restoreSpec(0)
	spec.Binding = storageTestBinding()
	if _, err := storage.persist(ctx, spec); err != nil {
		t.Fatal(err)
	}
	message := "held guest failure"
	if err := storage.RecordTerminal(ctx, retentionEvent(spec.DebugletID, -1, message)); err != nil {
		t.Fatal(err)
	}
	// A repeated report can never rewrite the result a duplicate would confirm.
	if err := storage.RecordTerminal(ctx, retentionEvent(spec.DebugletID, 0, "")); err != nil {
		t.Fatal(err)
	}
	if err := storage.finalize(ctx, spec.DebugletID); err != nil {
		t.Fatal(err)
	}

	event, found, err := storage.RetainedTerminal(ctx, spec.DebugletID)
	if err != nil || !found {
		t.Fatalf("terminal result did not outlive its run: found=%v error=%v", found, err)
	}
	if event.ExitCode != -1 || event.ErrorMessage == nil || *event.ErrorMessage != message {
		t.Fatalf("retained result was rewritten: %+v", event)
	}
	if event.Binding != storageTestBinding() || event.Attempts != 0 || !event.LastAttemptAt.IsZero() {
		t.Fatalf("retained event lost its identity or invented an attempt: %+v", event)
	}
	if event.RecordedAt.IsZero() {
		t.Fatal("retained event has no record time")
	}
	remaining, err := database.New(db).ListDebuglets(ctx, database.ListDebugletsParams{Limit: 8})
	if err != nil || len(remaining) != 0 {
		t.Fatalf("finalization did not delete the run: %d rows error=%v", len(remaining), err)
	}
}

// Only the binding a run was accepted under may count attempts against its
// retained event or release it, so a replacement session gains no authority
// over the results of the session it replaced.
func TestTerminalEventBindingScope(t *testing.T) {
	db := newSchedulerTestDB(t)
	storage := newTestStorage(t, db, storageTestEligibility)
	ctx, cancel := context.WithTimeout(context.Background(), retentionTestBound)
	defer cancel()

	id := uuid.New()
	if err := storage.RecordTerminal(ctx, retentionEvent(id, -1, "held guest failure")); err != nil {
		t.Fatal(err)
	}
	other := retentionOtherBinding()
	foreign := scheduler.TerminalAttempt{Attempts: 1, Failure: errors.New("foreign attempt")}
	if err := storage.NoteTerminalFailure(ctx, id, other, foreign); !errors.Is(err, scheduler.ErrTerminalNotRetained) {
		t.Fatalf("another session counted an attempt: %v", err)
	}
	if err := storage.ReleaseTerminal(ctx, id, other); !errors.Is(err, scheduler.ErrTerminalNotRetained) {
		t.Fatalf("another session released a retained result: %v", err)
	}
	event, found, err := storage.RetainedTerminal(ctx, id)
	if err != nil || !found || event.Attempts != 0 {
		t.Fatalf("foreign writes changed the retained event: %+v found=%v error=%v", event, found, err)
	}

	failure := errors.New("dispatcher unavailable")
	if err := storage.NoteTerminalFailure(ctx, id, storageTestBinding(), scheduler.TerminalAttempt{Attempts: 3, Failure: failure}); err != nil {
		t.Fatal(err)
	}
	event, found, err = storage.RetainedTerminal(ctx, id)
	if err != nil || !found || event.Attempts != 3 || event.LastError != failure.Error() || event.LastAttemptAt.IsZero() || event.Rejected {
		t.Fatalf("attempts were not persisted: %+v found=%v error=%v", event, found, err)
	}
	if err := storage.ReleaseTerminal(ctx, id, storageTestBinding()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := storage.RetainedTerminal(ctx, id); err != nil || found {
		t.Fatalf("acknowledged result stayed retained: found=%v error=%v", found, err)
	}
	// Releasing again is not a second acknowledgement.
	if err := storage.ReleaseTerminal(ctx, id, storageTestBinding()); !errors.Is(err, scheduler.ErrTerminalNotRetained) {
		t.Fatalf("released result was released twice: %v", err)
	}
}

// A restarted executor still finds the events it never had acknowledged, and
// the diagnostics it retained stay bounded.
func TestTerminalEventsSurviveRestart(t *testing.T) {
	db := newSchedulerTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), retentionTestBound)
	defer cancel()

	first := newTestStorage(t, db, storageTestEligibility)
	ids := make([]uuid.UUID, 3)
	for i := range ids {
		ids[i] = uuid.New()
		if err := first.RecordTerminal(ctx, retentionEvent(ids[i], int32(i), "")); err != nil {
			t.Fatal(err)
		}
	}
	long := errors.New(strings.Repeat("diagnostic ", 512))
	if err := first.NoteTerminalFailure(ctx, ids[0], storageTestBinding(), scheduler.TerminalAttempt{Attempts: 1, Failure: long}); err != nil {
		t.Fatal(err)
	}
	if err := first.ReleaseTerminal(ctx, ids[2], storageTestBinding()); err != nil {
		t.Fatal(err)
	}
	if err := first.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	// The successor reads the same database with a fresh in-memory core.
	successor := newTestStorage(t, db, storageTestEligibility)
	if err := successor.RestoreFromDatabase(ctx); err != nil {
		t.Fatal(err)
	}
	if got := successor.RetainedTerminalCount(); got != 2 {
		t.Fatalf("restore counted %d unreconciled events, want 2", got)
	}
	events, err := successor.ListAllRetainedTerminals(ctx, 16)
	if err != nil || len(events) != 2 {
		t.Fatalf("listing unreconciled events: %d error=%v", len(events), err)
	}
	seen := map[uuid.UUID]scheduler.TerminalEvent{}
	for _, event := range events {
		seen[event.DebugletID] = event
	}
	if _, ok := seen[ids[2]]; ok {
		t.Fatal("an acknowledged result was still listed")
	}
	noted, ok := seen[ids[0]]
	if !ok || noted.Attempts != 1 {
		t.Fatalf("attempt count did not survive restart: %+v", noted)
	}
	if len(noted.LastError) > maxRetainedDiagnostic+len("…") {
		t.Fatalf("retained diagnostic is unbounded: %d bytes", len(noted.LastError))
	}
	if err := successor.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	// A shut-down core admits no new reads instead of racing database closure.
	if _, _, err := successor.RetainedTerminal(ctx, ids[0]); !errors.Is(err, scheduler.ErrClosed) {
		t.Fatalf("closed storage still admitted a read: %v", err)
	}
}

// A session lists only what it can still deliver. Results belonging to a
// replaced session and results the dispatcher already refused stay retained
// and inspectable, but never occupy a reconciliation pass.
func TestListRetainedTerminalsExcludesUndeliverable(t *testing.T) {
	db := newSchedulerTestDB(t)
	storage := newTestStorage(t, db, storageTestEligibility)
	ctx, cancel := context.WithTimeout(context.Background(), retentionTestBound)
	defer cancel()

	stale := retentionOtherBinding()
	base := time.Now().UTC().Add(-time.Hour)
	for i := range 40 {
		event := retentionEvent(uuid.New(), -1, "")
		event.Binding = stale
		event.RecordedAt = base.Add(time.Duration(i) * time.Second)
		if err := storage.RecordTerminal(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	refused := uuid.New()
	refusedEvent := retentionEvent(refused, -1, "")
	refusedEvent.RecordedAt = base
	if err := storage.RecordTerminal(ctx, refusedEvent); err != nil {
		t.Fatal(err)
	}
	attempt := scheduler.TerminalAttempt{Attempts: 1, Rejected: true, Failure: errors.New("run belongs to another session")}
	if err := storage.NoteTerminalFailure(ctx, refused, storageTestBinding(), attempt); err != nil {
		t.Fatal(err)
	}
	live := uuid.New()
	liveEvent := retentionEvent(live, 0, "")
	liveEvent.RecordedAt = time.Now().UTC()
	if err := storage.RecordTerminal(ctx, liveEvent); err != nil {
		t.Fatal(err)
	}

	events, err := storage.ListRetainedTerminals(ctx, storageTestBinding(), 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].DebugletID != live {
		t.Fatalf("deliverable listing returned %d events, want only the live one", len(events))
	}
	all, err := storage.ListAllRetainedTerminals(ctx, 64)
	if err != nil || len(all) != 42 {
		t.Fatalf("undeliverable results stopped being inspectable: %d error=%v", len(all), err)
	}
	event, found, err := storage.RetainedTerminal(ctx, refused)
	if err != nil || !found || !event.Rejected || event.Attempts != 1 || event.LastError == "" {
		t.Fatalf("refused result lost its evidence: %+v found=%v error=%v", event, found, err)
	}
	if events, err := storage.ListRetainedTerminals(ctx, controlsession.Binding{}, 32); err != nil || events != nil {
		t.Fatalf("invalid binding listed deliverable work: %d error=%v", len(events), err)
	}
}
