package rpc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func assertMutationSignalOpen(t *testing.T, signal <-chan struct{}, reason string) {
	t.Helper()
	select {
	case <-signal:
		t.Error(reason)
	default:
	}
}

func keepTestMutation(t *testing.T, mutation *Mutation) *Mutation {
	t.Helper()
	// No user work is left in these primitive fixtures. Gated watcher tests
	// register their release cleanup later, so it runs before this final join.
	t.Cleanup(mutation.Finish)
	return mutation
}

func TestMutationAdmission(t *testing.T) {
	owner := newTestOwner(t, "executor")
	t.Cleanup(func() { owner.Retire() })
	if mutation, err := owner.AdmitMutation(context.Background()); mutation != nil || !errors.Is(err, ErrSessionUnavailable) {
		t.Fatal("ordinary admission accepted unavailable owner")
	}
	setup, err := owner.AdmitSetup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keepTestMutation(t, setup)
	if setup.Owner() != owner || !setup.IsSetup() || !setup.Live() {
		t.Fatal("setup ownership is incorrect")
	}
	setup.Finish()
	assertMutationSignalOpen(t, owner.MutationsDrained(), "active owner drained after setup completion")
	if !owner.MarkRegistered() {
		t.Fatal("registration failed")
	}
	mutation, err := owner.AdmitMutation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keepTestMutation(t, mutation)
	if mutation.Owner() != owner || mutation.IsSetup() || !mutation.Live() {
		t.Fatal("ordinary ownership is incorrect")
	}
	mutation.Finish()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, ctx := range []context.Context{canceled, expired} {
		for _, admit := range []func(context.Context) (*Mutation, error){owner.AdmitMutation, owner.AdmitSetup} {
			if got, err := admit(ctx); got != nil || !errors.Is(err, ctx.Err()) {
				t.Fatal("pre-canceled root was admitted or lost cancellation identity")
			}
		}
	}
	owner.Retire()
	awaitOwnerSignal(t, owner.MutationsDrained())
	for _, admit := range []func(context.Context) (*Mutation, error){owner.AdmitMutation, owner.AdmitSetup} {
		if got, err := admit(context.Background()); got != nil || !errors.Is(err, ErrSessionRetired) {
			t.Fatal("retired owner admitted a fresh root")
		}
	}
}

func TestMutationCancellationDoesNotDrain(t *testing.T) {
	for _, retire := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller_cancel", true: "retirement"}[retire], func(t *testing.T) {
			owner := newTestOwner(t, "executor")
			t.Cleanup(func() { owner.Retire() })
			owner.MarkRegistered()
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			mutation, err := owner.AdmitMutation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			keepTestMutation(t, mutation)
			cause := errors.New("caller stopped local work")
			if retire {
				owner.Retire()
				cause = ErrSessionRetired
			} else {
				cancel(cause)
			}
			awaitOwnerSignal(t, mutation.Context().Done())
			if !errors.Is(context.Cause(mutation.Context()), cause) || !mutation.Live() {
				t.Fatal("cancellation lost its cause or released ownership")
			}
			waitCtx, waitCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer waitCancel()
			select {
			case <-owner.MutationsDrained():
				t.Fatal("cancellation falsely drained a live ticket")
			case <-waitCtx.Done():
			}
			if !mutation.Live() {
				t.Fatal("waiter timeout released the ticket")
			}
			mutation.Finish()
			awaitOwnerSignal(t, mutation.watcherDone)
			awaitOwnerSignal(t, mutation.finishedDone)
			if mutation.Live() {
				t.Fatal("finished ticket remains live")
			}
			if !retire {
				assertMutationSignalOpen(t, owner.MutationsDrained(), "active owner drained at zero references")
				owner.Retire()
			}
			awaitOwnerSignal(t, owner.MutationsDrained())
		})
	}
}

func TestMutationForkHasIndependentLifetime(t *testing.T) {
	for _, setup := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "setup"}[setup], func(t *testing.T) {
			owner := newTestOwner(t, "executor")
			t.Cleanup(func() { owner.Retire() })
			owner.MarkRegistered()
			admit := owner.AdmitMutation
			if setup {
				admit = owner.AdmitSetup
			}
			parent, err := admit(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			keepTestMutation(t, parent)
			child, err := parent.Fork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			keepTestMutation(t, child)
			if child.Owner() != owner || child.IsSetup() != setup {
				t.Fatal("fork changed owner or admission kind")
			}
			parent.Finish()
			if !child.Live() || child.Context().Err() != nil {
				t.Fatal("parent Finish canceled or completed its independent child")
			}
			if got, err := parent.Fork(context.Background()); got != nil || !errors.Is(err, ErrMutationFinished) {
				t.Fatal("finished parent admitted a continuation")
			}
			owner.Retire()
			awaitOwnerSignal(t, child.Context().Done())
			assertMutationSignalOpen(t, owner.MutationsDrained(), "retirement discarded child ownership")
			// Retirement blocks roots, but this live child still owns an admitted
			// same-owner continuation. Its caller explicitly supplies the context.
			continuation, err := child.Fork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			keepTestMutation(t, continuation)
			if continuation.Owner() != owner || continuation.IsSetup() != setup {
				t.Fatal("retired continuation changed authority")
			}
			awaitOwnerSignal(t, continuation.Context().Done())
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if got, err := child.Fork(canceled); got != nil || !errors.Is(err, context.Canceled) {
				t.Fatal("pre-canceled continuation admitted")
			}
			child.Finish()
			assertMutationSignalOpen(t, owner.MutationsDrained(), "retired continuation was not counted")
			continuation.Finish()
			awaitOwnerSignal(t, owner.MutationsDrained())
		})
	}
}

func TestMutationFinishJoinsRetirementWatcher(t *testing.T) {
	owner := newTestOwner(t, "executor")
	t.Cleanup(func() { owner.Retire() })
	owner.MarkRegistered()
	mutation, err := owner.AdmitMutation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keepTestMutation(t, mutation)
	entered, gate := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate) }) }
	t.Cleanup(release)
	originalCancel := mutation.cancel
	var cancelCalls atomic.Int32
	// This per-ticket wrapper holds the actual retirement watcher. It is set
	// before Done closes and before any Finish starts; channel close publishes
	// it to the watcher. No global hook or separate fake completion is involved.
	mutation.cancel = func(cause error) {
		if cancelCalls.Add(1) == 1 {
			close(entered)
			<-gate
		}
		originalCancel(cause)
	}
	retire := startOwnerTestCall(t, release, owner.Retire)
	awaitOwnerSignal(t, entered)
	if !retire.wait(t) {
		t.Fatal("retirement failed")
	}
	// Retire already returned while its cancellation hook is held. The owner
	// guard must therefore be available to reject fresh work and inspect Live.
	if !mutation.Live() {
		t.Fatal("retirement released live ownership")
	}
	if got, err := owner.AdmitSetup(context.Background()); got != nil || !errors.Is(err, ErrSessionRetired) {
		t.Fatal("retirement admitted setup")
	}
	first := startOwnerTestCall(t, release, func() bool { mutation.Finish(); return true })
	awaitOwnerSignal(t, mutation.Context().Done()) // Finish canceled outside the held watcher.
	second := startOwnerTestCall(t, release, func() bool { mutation.Finish(); return true })
	if mutation.Live() {
		t.Fatal("Finish did not close fork admission before joining")
	}
	if got, err := mutation.Fork(context.Background()); got != nil || !errors.Is(err, ErrMutationFinished) {
		t.Fatal("finishing parent admitted a fork")
	}
	select {
	case <-first.joined:
		t.Error("Finish returned before its retirement watcher joined")
	case <-second.joined:
		t.Error("concurrent Finish bypassed the shared completion")
	case <-owner.MutationsDrained():
		t.Error("owner drained while the cancellation watcher remained held")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	if !first.wait(t) || !second.wait(t) {
		t.Error("Finish callers did not complete")
	}
	awaitOwnerSignal(t, mutation.watcherDone)
	awaitOwnerSignal(t, owner.MutationsDrained())
	if cancelCalls.Load() != 2 {
		t.Errorf("concurrent Finish repeated cancellation: %d calls", cancelCalls.Load())
	}
}

func TestMutationForkRacesFinishAndRetirement(t *testing.T) {
	for range 100 {
		owner := newTestOwner(t, "executor")
		owner.MarkRegistered()
		parent, err := owner.AdmitMutation(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		keepTestMutation(t, parent)
		start := make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(start) }) }
		type forkResult struct {
			child *Mutation
			err   error
		}
		result := make(chan forkResult, 1)
		resultConsumed := false
		// Registered before the actors' join cleanups, so even an early
		// assertion failure recovers and finishes a successfully forked child.
		t.Cleanup(func() {
			if !resultConsumed {
				select {
				case got := <-result:
					if got.child != nil {
						got.child.Finish()
					}
				case <-time.After(ownerTestTimeout):
					t.Error("fork caller did not publish its owned result")
				}
			}
		})
		fork := startOwnerTestCall(t, release, func() bool {
			<-start
			child, err := parent.Fork(context.Background())
			result <- forkResult{child, err}
			return true
		})
		finish := startOwnerTestCall(t, release, func() bool { <-start; parent.Finish(); return true })
		retire := startOwnerTestCall(t, release, func() bool { <-start; return owner.Retire() })
		// All actors are joined before reading the fork outcome or final state.
		release()
		fork.wait(t)
		finish.wait(t)
		retire.wait(t)
		got := <-result
		resultConsumed = true
		if got.child != nil {
			keepTestMutation(t, got.child)
			if got.err != nil || got.child.Owner() != owner || !got.child.Live() {
				t.Fatal("successful racing fork lost ownership")
			}
			assertMutationSignalOpen(t, owner.MutationsDrained(), "racing fork produced a false zero-reference drain")
			got.child.Finish()
		} else if !errors.Is(got.err, ErrMutationFinished) {
			t.Fatalf("unexpected fork result: %v", got.err)
		}
		awaitOwnerSignal(t, owner.MutationsDrained())
	}
}
