package memory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

func boundSpec() scheduler.Spec {
	s := distinctSpecs(1)[0]
	s.Binding = controlsession.Binding{Incarnation: "c31f0dc2-3f96-4a5a-aa2a-a4bcc16d88fb", SessionID: "6f2f15d8-f982-44a8-b22c-8d80fa5f8b62"}
	return s
}
func anotherBinding(b controlsession.Binding) controlsession.Binding {
	b.SessionID = uuid.NewString()
	return b
}

type boundResult struct {
	found bool
	err   error
}

func boundCall[T any](t *testing.T, release func(), call func() T) <-chan T {
	t.Helper()
	result, joined := make(chan T, 1), make(chan struct{})
	go func() { defer close(joined); result <- call() }()
	t.Cleanup(func() { release(); await(t, joined, "bound operation caller") })
	return result
}
func boundAwait[T any](t *testing.T, result <-chan T, label string) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(testBound):
		t.Fatalf("timed out waiting for %s", label)
	}
	var zero T
	return zero
}
func boundCleanup(t *testing.T, m *MemoryStorage, release func()) {
	t.Helper()
	t.Cleanup(func() {
		release()
		ctx, cancel := context.WithTimeout(context.Background(), testBound)
		defer cancel()
		if err := m.Shutdown(ctx); errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("bound scheduler did not join: %v", err)
		}
	})
}

func TestCancelBoundPreservesOtherIncarnations(t *testing.T) {
	m := newTestStorage(t)
	boundCleanup(t, m, func() {})
	ctx, cancel := context.WithTimeout(context.Background(), testBound)
	defer cancel()
	original, sibling := boundSpec(), boundSpec()
	for _, s := range []scheduler.Spec{original, sibling} {
		if err := m.Insert(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	for _, wrong := range []controlsession.Binding{{}, anotherBinding(original.Binding)} {
		if found, err := m.CancelBound(ctx, original.DebugletID, wrong, errors.New("wrong cause")); found || !errors.Is(err, scheduler.ErrBindingMismatch) {
			t.Fatalf("foreign cancellation=%t/%v", found, err)
		}
	}
	m.mu.RLock()
	o := m.owners[original.DebugletID]
	untouched := o != nil && o.phase == queued && o.cause == nil && o.attempt == nil && m.tq.Len() == 2
	m.mu.RUnlock()
	if !untouched {
		t.Fatal("rejected binding altered queued owner or cause")
	}
	if found, err := m.CancelBound(ctx, original.DebugletID, original.Binding, nil); !found || err != nil {
		t.Fatalf("matching cancel=%t/%v", found, err)
	}
	replacement := original
	replacement.Binding = anotherBinding(original.Binding)
	if err := m.Insert(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if found, err := m.CancelBound(ctx, replacement.DebugletID, original.Binding, nil); found || !errors.Is(err, scheduler.ErrBindingMismatch) {
		t.Fatalf("old binding canceled reused UUID: %t/%v", found, err)
	}
	m.mu.RLock()
	fresh := m.owners[replacement.DebugletID]
	other := m.owners[sibling.DebugletID]
	kept := fresh != nil && fresh.spec.Binding == replacement.Binding && fresh.phase == queued && other != nil && other.phase == queued
	m.mu.RUnlock()
	if !kept {
		t.Fatal("replacement or sibling was altered")
	}
}

func TestCancelBoundOwnsPersistingAdmission(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	var inspected, deleted atomic.Int32
	m := newTestPersistentStorage(t, func(_ context.Context, s scheduler.Spec) (scheduler.Spec, error) {
		close(entered)
		<-release
		return s, nil
	}, func(context.Context, uuid.UUID) error { deleted.Add(1); return nil }, func(context.Context, uuid.UUID, controlsession.Binding) error { inspected.Add(1); return nil })
	boundCleanup(t, m, open)
	ctx, cancel := context.WithTimeout(context.Background(), testBound)
	defer cancel()
	s := boundSpec()
	inserted := boundCall(t, open, func() error { return m.Insert(ctx, s) })
	if !await(t, entered, "held persistence") {
		return
	}
	canceled := boundCall(t, open, func() boundResult { f, e := m.CancelBound(ctx, s.DebugletID, s.Binding, nil); return boundResult{f, e} })
	if !waitFor(t, "cancellation owned before persistence returns", func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		o := m.owners[s.DebugletID]
		return o != nil && o.attempt != nil
	}) {
		return
	}
	if inspected.Load() != 0 {
		t.Fatal("persisting core owner was classified through absent-row SQL")
	}
	short, end := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := m.Shutdown(short)
	end()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown lost admitted persistence: %v", err)
	}
	open()
	if err := boundAwait(t, inserted, "successful insert"); err != nil {
		t.Fatal(err)
	}
	result := boundAwait(t, canceled, "joined cancellation")
	if !result.found || result.err != nil || deleted.Load() != 1 || inspected.Load() != 0 {
		t.Fatalf("accepted cancel=%+v delete=%d inspect=%d", result, deleted.Load(), inspected.Load())
	}
}

func TestCancelBoundAbsentInspectionJoinsWithoutCancelingLaterInsert(t *testing.T) {
	entered, release, queryDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	m := newTestPersistentStorage(t, nil, nil, func(context.Context, uuid.UUID, controlsession.Binding) error {
		defer close(queryDone)
		close(entered)
		<-release
		return nil
	})
	boundCleanup(t, m, open)
	ctx, cancel := context.WithTimeout(context.Background(), testBound)
	defer cancel()
	s := boundSpec()
	canceled := boundCall(t, open, func() boundResult { f, e := m.CancelBound(ctx, s.DebugletID, s.Binding, nil); return boundResult{f, e} })
	if !await(t, entered, "absent-owner inspection") {
		return
	}
	if err := m.Insert(ctx, s); err != nil {
		t.Fatal(err)
	}
	short, end := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := m.Shutdown(short)
	end()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown returned before actual inspector: %v", err)
	}
	open()
	result := boundAwait(t, canceled, "absent cancellation")
	if result.found || result.err != nil {
		t.Fatalf("absent cancellation=%+v", result)
	}
	if !await(t, queryDone, "actual inspector return") {
		return
	}
	if err := m.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	m.mu.RLock()
	o := m.owners[s.DebugletID]
	intact := o != nil && o.phase == queued && o.cause == nil && o.attempt == nil
	m.mu.RUnlock()
	if !intact {
		t.Fatal("absent-at-admission cancellation touched the later Insert")
	}
}

func TestCancelBoundRejoinsCompletedOwnerWithoutRow(t *testing.T) {
	var inspected, deleted atomic.Int32
	m := newTestPersistentStorage(t, func(_ context.Context, s scheduler.Spec) (scheduler.Spec, error) { return s, nil }, func(context.Context, uuid.UUID) error { deleted.Add(1); return nil }, func(context.Context, uuid.UUID, controlsession.Binding) error {
		inspected.Add(1)
		return scheduler.ErrBindingMismatch
	})
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	started := make(chan struct{})
	cleanupErr := errors.New("owned resource release failed")
	m.RegisterOnStart(func(ctx context.Context, _ scheduler.Spec) scheduler.Completion {
		close(started)
		<-ctx.Done()
		return scheduler.Completion{CleanupErr: cleanupErr}
	})
	boundCleanup(t, m, stop)
	loop := boundCall(t, stop, func() error { return m.StartLoop(ctx) })
	s := boundSpec()
	if err := m.Insert(ctx, s); err != nil {
		t.Fatal(err)
	}
	if !await(t, started, "active callback") {
		return
	}
	join, end := context.WithTimeout(context.Background(), testBound)
	defer end()
	if found, err := m.CancelBound(join, s.DebugletID, anotherBinding(s.Binding), nil); found || !errors.Is(err, scheduler.ErrBindingMismatch) {
		t.Fatalf("active foreign cancel=%t/%v", found, err)
	}
	if found, err := m.CancelBound(join, s.DebugletID, s.Binding, nil); !found || !errors.Is(err, cleanupErr) {
		t.Fatalf("completed cancel=%t/%v", found, err)
	}
	if err := m.Shutdown(join); !errors.Is(err, cleanupErr) {
		t.Fatalf("shutdown=%v", err)
	}
	if found, err := m.CancelBound(join, s.DebugletID, s.Binding, nil); !found || !errors.Is(err, cleanupErr) {
		t.Fatalf("closed repeated join lost result: %t/%v", found, err)
	}
	if deleted.Load() != 1 || inspected.Load() != 0 {
		t.Fatalf("rejoin performed new SQL: delete=%d inspect=%d", deleted.Load(), inspected.Load())
	}
	err := boundAwait(t, loop, "closed scheduler loop")
	if !errors.Is(err, scheduler.ErrClosed) && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
