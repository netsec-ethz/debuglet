package executor

import (
	"context"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// The scheduler a session holds offers only bound cancellation, so a fixture
// cannot be asked for the unbound or queue-only deletions at all.
type abortTestScheduler struct {
	cancel func(context.Context, uuid.UUID, error) (bool, error)
}

func (s *abortTestScheduler) Insert(context.Context, scheduler.Spec) error {
	return errors.New("unexpected fixture Insert")
}
func (s *abortTestScheduler) CancelBound(ctx context.Context, id uuid.UUID, binding controlsession.Binding, cause error) (bool, error) {
	if binding != operationBinding() {
		return false, scheduler.ErrBindingMismatch
	}
	return s.cancel(ctx, id, cause)
}
func (*abortTestScheduler) RegisterOnStart(scheduler.StartFunc) {}
func (*abortTestScheduler) RegisterFailed(scheduler.FailedFunc) {}
func (*abortTestScheduler) StartLoop(context.Context) error {
	return errors.New("unexpected fixture loop")
}
func (*abortTestScheduler) Shutdown(context.Context) error { return nil }

func TestAbortWaitsForSchedulerCompletion(t *testing.T) {
	id := uuid.New()
	entered, release := make(chan struct{}), make(chan struct{})
	var matched atomic.Bool
	storage := &abortTestScheduler{cancel: func(ctx context.Context, got uuid.UUID, cause error) (bool, error) {
		matched.Store(got == id && cause.Error() == "requested cause")
		close(entered)
		select {
		case <-release:
			return true, nil
		case <-ctx.Done():
			return true, ctx.Err()
		}
	}}
	_, client := newExecutorRPCFixture(t, newOperationPeer(), storage)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var result error
	go func() {
		_, result = client.Abort(ctx, &pb.AbortRequest{DebugletId: id.String(), Reason: "requested cause"})
		close(done)
	}()
	t.Cleanup(func() { cancel(); operationAwait(t, done, "Abort RPC") })
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	if !operationAwait(t, entered, "scheduler Cancel") {
		return
	}
	select {
	case <-done:
		t.Fatal("Abort acknowledged before scheduler completion")
	default:
	}
	once.Do(func() { close(release) })
	if !operationAwait(t, done, "Abort acknowledgement") {
		return
	}
	if result != nil || !matched.Load() {
		t.Fatalf("Abort bypassed cancellation owner: result=%v matched=%t", result, matched.Load())
	}
}

func TestAbortPreservesSchedulerErrorsAndNotFound(t *testing.T) {
	want := errors.New("canonical finalization failed")
	storage := &abortTestScheduler{cancel: func(context.Context, uuid.UUID, error) (bool, error) { return true, want }}
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
	req := &pb.AbortRequest{DebugletId: uuid.NewString()}
	if _, err := e.OnAbort(context.Background(), operationBinding(), req); !errors.Is(err, want) {
		t.Fatalf("cleanup error lost: %v", err)
	}
	storage.cancel = func(context.Context, uuid.UUID, error) (bool, error) { return false, nil }
	if _, err := e.OnAbort(context.Background(), operationBinding(), req); status.Code(err) != codes.NotFound {
		t.Fatalf("retired/not-found behavior changed: %v", err)
	}
	storage.cancel = func(ctx context.Context, _ uuid.UUID, cause error) (bool, error) {
		if !errors.Is(cause, context.Canceled) {
			t.Error("empty reason did not use cancellation cause")
		}
		return false, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.OnAbort(ctx, operationBinding(), req); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller context identity lost: %v", err)
	}
}
