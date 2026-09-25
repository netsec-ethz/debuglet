package executor

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
)

// A control loss ends delivery instead of retrying without authority. The
// chosen result is retained under the run's own binding, survives the session
// that produced it, and the successor neither redelivers nor releases it.
func TestRecoveryRetainsUndeliveredTerminalResult(t *testing.T) {
	peer := newOperationPeer()
	f := newRecoveryHarness(t, peer)
	running := make(chan struct{})
	runtime := &operationRuntime{run: func(ctx context.Context, _ chan<- []byte) error {
		close(running)
		<-ctx.Done()
		return context.Cause(ctx)
	}}
	s1, owner1, client1 := f.start(func(e *Executor) {
		e.newRuntime = func(spec scheduler.Spec) runtimeDebuglet {
			runtime.close = func(context.Context) error { e.limiter.RemoveDebuglet(spec.DebugletID); return nil }
			return runtime
		}
	})
	ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	defer cancel()
	oldBinding, ok := s1.executor.Bidi.Binding()
	if !ok {
		t.Fatal("ready session lost binding")
	}
	active := uuid.New()
	if _, err := client1.Upload(ctx, recoveryUpload(oldBinding, active, false)); err != nil {
		t.Fatal(err)
	}
	if !operationAwait(t, running, "running guest before disconnect") {
		return
	}
	if !f.server.RemoveClient(owner1) {
		t.Fatal("failed to retire the actual current transport")
	}
	if !operationAwait(t, s1.Lost(), "immediate transport loss") {
		return
	}
	if err := s1.Wait(ctx); err != nil {
		t.Fatalf("revoked session did not join: %v", err)
	}
	if peer.reportCalls.Load() != 0 {
		t.Fatal("a revoked session sent a terminal report")
	}

	// The evidence outlives both the run row and the session that chose it.
	var incarnation, sessionID, lastError string
	var exitCode, attempts int64
	err := f.db.QueryRowContext(ctx,
		"SELECT dispatcher_incarnation, session_id, exit_code, attempts, last_error FROM debuglet_exits WHERE debuglet_id = ?",
		active.String()).Scan(&incarnation, &sessionID, &exitCode, &attempts, &lastError)
	if err != nil {
		t.Fatalf("terminal result was not retained: %v", err)
	}
	if incarnation != oldBinding.Incarnation || sessionID != oldBinding.SessionID {
		t.Fatalf("retained event changed ownership: %q/%q", incarnation, sessionID)
	}
	if exitCode != -1 || attempts != 0 || lastError == "" {
		t.Fatalf("retained event misdescribes its delivery: code=%d attempts=%d error=%q", exitCode, attempts, lastError)
	}
	var rows int
	if err := f.db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ?", active).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("joined finalizer did not retire its run row: rows=%d error=%v", rows, err)
	}

	s2, _, _ := f.start(nil)
	newBinding, ok := s2.executor.Bidi.Binding()
	if !ok || newBinding == oldBinding {
		t.Fatal("successor did not negotiate a distinct session")
	}
	storage := s2.storage.(*sqlite.SqliteStorage)
	if got := storage.RetainedTerminalCount(); got != 1 {
		t.Fatalf("restore counted %d unreconciled results, want 1", got)
	}
	// A successor must not deliver, release or rewrite the old session's work.
	s2.executor.reconcileTerminals(ctx, newBinding)
	if peer.reportCalls.Load() != 0 {
		t.Fatal("successor redelivered another session's terminal result")
	}
	event, found, err := storage.RetainedTerminal(ctx, active)
	if err != nil || !found {
		t.Fatalf("retained result became uninspectable: found=%v error=%v", found, err)
	}
	if event.Binding != oldBinding || event.ExitCode != -1 || event.Attempts != 0 {
		t.Fatalf("retained result changed under the successor: %+v", event)
	}
	s2.Stop(nil)
	if err := s2.Wait(ctx); err != nil {
		t.Fatalf("successor did not join before harness cleanup: %v", err)
	}
}
