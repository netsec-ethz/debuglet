package memory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

func TestMemoryCancelSignalsThenJoins(t *testing.T) {
	m := newTestStorage(t)
	ctx, stopLoop := context.WithCancel(context.Background())
	loopDone := make(chan error, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	open := func() { releaseOnce.Do(func() { close(release) }) }
	cleanupErr := errors.New("joined resource close failure")
	t.Cleanup(func() {
		open()
		stopLoop()
		joinCtx, cancel := context.WithTimeout(context.Background(), testBound)
		defer cancel()
		if err := m.Shutdown(joinCtx); err != nil && !errors.Is(err, cleanupErr) {
			t.Error(err)
		}
		select {
		case err := <-loopDone:
			if !errors.Is(err, context.Canceled) && !errors.Is(err, scheduler.ErrClosed) {
				t.Error(err)
			}
		case <-joinCtx.Done():
			t.Error("dispatcher did not join")
		}
	})
	started := make(chan struct{})
	observedCause := make(chan error, 1)
	var calls atomic.Int32
	m.RegisterOnStart(func(ctx context.Context, _ scheduler.Spec) scheduler.Completion {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		observedCause <- context.Cause(ctx)
		<-release
		return scheduler.Completion{CleanupErr: cleanupErr}
	})
	spec := distinctSpecs(1)[0]
	if err := m.Insert(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	go func() { loopDone <- m.StartLoop(ctx) }()
	if !await(t, started, "memory callback entry") {
		return
	}
	cause := errors.New("selected cause")
	waitCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	first := make(chan error, 1)
	go func() {
		found, err := m.Cancel(waitCtx, spec.DebugletID, cause)
		if !found {
			err = errors.New("active owner absent")
		}
		first <- err
	}()
	select {
	case got := <-observedCause:
		if !errors.Is(got, cause) {
			t.Fatalf("cause=%v", got)
		}
	case <-time.After(testBound):
		t.Fatal("Cancel waited without signaling callback")
	}
	select {
	case err := <-first:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("callback not joined but Cancel returned %v", err)
		}
	case <-time.After(testBound):
		t.Fatal("caller deadline did not bound wait")
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancelShutdown()
	if err := m.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held callback Shutdown=%v", err)
	}
	if q, inflight := queueState(m); q != 0 || inflight != 1 {
		t.Fatalf("timed-out join lost owner: %d/%d", q, inflight)
	}
	open()
	joinCtx, cancelJoin := context.WithTimeout(context.Background(), testBound)
	defer cancelJoin()
	if err := m.Shutdown(joinCtx); !errors.Is(err, cleanupErr) {
		t.Fatalf("joined completion=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("callback reran")
	}
	if err := m.Shutdown(joinCtx); !errors.Is(err, cleanupErr) {
		t.Fatal("repeat shutdown lost immutable cleanup error")
	}
}

func TestMemoryNaturalCompletionRacesCancel(t *testing.T) {
	m := newTestStorage(t)
	h := newLoopHarness(t, m)
	entered := make(chan scheduler.Spec, 1)
	releases := make(chan chan struct{}, 1)
	var calls atomic.Int32
	m.RegisterOnStart(func(_ context.Context, spec scheduler.Spec) scheduler.Completion {
		calls.Add(1)
		entered <- spec
		var gate <-chan struct{}
		select {
		case gate = <-releases:
		case <-h.release:
			return scheduler.Completion{}
		}
		select {
		case <-gate:
		case <-h.release:
		}
		return scheduler.Completion{}
	})
	h.start()
	for _, spec := range distinctSpecs(100) {
		if err := m.Insert(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
		if !callbackID(t, entered, spec.DebugletID) {
			return
		}
		gate := make(chan struct{})
		releases <- gate
		ctx, cancel := context.WithTimeout(context.Background(), testBound)
		done := make(chan error, 1)
		go func() { _, err := m.Cancel(ctx, spec.DebugletID, context.Canceled); done <- err }()
		close(gate)
		select {
		case err := <-done:
			cancel()
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			cancel()
			t.Fatal("completion/cancel race did not join")
		}
		if !waitFor(t, "completed incarnation retirement", func() bool {
			m.mu.RLock()
			defer m.mu.RUnlock()
			_, exists := m.owners[spec.DebugletID]
			return !exists
		}) {
			return
		}
		if found, err := m.Cancel(context.Background(), spec.DebugletID, nil); found || err != nil {
			t.Fatalf("retired owner remained: %t %v", found, err)
		}
	}
	if calls.Load() != 100 {
		t.Fatalf("callbacks=%d want100", calls.Load())
	}
}
