package rpc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
)

const ownerTestTimeout = 2 * time.Second

type ownerTestCall struct {
	result chan bool
	joined chan struct{}
}

// Every caller is joined even if its result was consumed or an assertion fails.
// Release belongs to the test and runs before waiting on any blocked caller.
func startOwnerTestCall(t *testing.T, release func(), f func() bool) ownerTestCall {
	t.Helper()
	call := ownerTestCall{result: make(chan bool, 1), joined: make(chan struct{})}
	t.Cleanup(func() {
		if release != nil {
			release()
		}
		select {
		case <-call.joined:
		case <-time.After(ownerTestTimeout):
			t.Error("session owner caller did not join after releasing its gate")
		}
	})
	go func() {
		defer close(call.joined)
		call.result <- f()
	}()
	return call
}

func (call ownerTestCall) wait(t *testing.T) bool {
	t.Helper()
	awaitOwnerSignal(t, call.joined)
	return <-call.result
}

func awaitOwnerSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(ownerTestTimeout):
		t.Fatal("timed out waiting for session owner signal")
	}
}

func newTestOwner(t *testing.T, id string) *SessionOwner {
	t.Helper()
	owner, err := NewSessionOwner(id, testOwnerBinding(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func testOwnerBinding() controlsession.Binding {
	return controlsession.Binding{Incarnation: "cd678a91-a1ba-4def-8192-123456789abc", SessionID: "92ab28aa-189a-4fd0-9924-abcdef123456"}
}

func TestSessionOwnerCommitRetirement(t *testing.T) {
	t.Run("held_commit", func(t *testing.T) {
		owner := newTestOwner(t, "executor")
		entered, releaseGate := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseGate) }) }
		var published atomic.Int32
		commit := startOwnerTestCall(t, release, func() bool {
			return owner.CommitActive(func() {
				close(entered)
				<-releaseGate
				published.Add(1)
			})
		})
		awaitOwnerSignal(t, entered)
		requested := make(chan struct{})
		retire := startOwnerTestCall(t, release, func() bool {
			close(requested)
			return owner.Retire()
		})
		awaitOwnerSignal(t, requested)

		// Atomic observations and another owner's transitions must not acquire
		// this held commit guard or a shared/global lock.
		observe := startOwnerTestCall(t, release, func() bool { return owner.Active() && !owner.Available() })
		if !observe.wait(t) {
			t.Error("owner retired before its held commit exited")
		}
		other := newTestOwner(t, "unrelated")
		independent := startOwnerTestCall(t, release, func() bool { return other.MarkRegistered() && other.Retire() })
		if !independent.wait(t) {
			t.Error("unrelated owner transition failed")
		}

		// The commit has explicitly entered. This is a bounded observation of
		// forbidden early completion, not a sleep used to establish entry.
		select {
		case <-retire.joined:
			t.Error("retirement completed while the commit remained held")
		case <-owner.Done():
			t.Error("retirement signaled while the commit remained held")
		case <-time.After(20 * time.Millisecond):
		}
		release()
		if !commit.wait(t) || !retire.wait(t) || published.Load() != 1 {
			t.Error("admitted commit and subsequent retirement did not complete once")
		}
		awaitOwnerSignal(t, owner.Done())
		if owner.Active() || owner.Available() {
			t.Error("retired owner remains active or available")
		}
	})

	t.Run("retire_before_commit", func(t *testing.T) {
		owner := newTestOwner(t, "executor")
		if !owner.Retire() {
			t.Fatal("initial retirement failed")
		}
		called := false
		if owner.CommitActive(func() { called = true }) || called {
			t.Error("retired owner admitted a delayed publication")
		}
		if owner.MarkRegistered() || owner.Retire() || owner.Active() || owner.Available() {
			t.Error("retired owner reactivated or retired twice")
		}
		select {
		case <-owner.Registered():
			t.Error("retirement falsely signaled successful registration")
		default:
		}
		awaitOwnerSignal(t, owner.Done())
	})
}

func TestSessionOwnerRegistrationWaitsForCommit(t *testing.T) {
	owner := newTestOwner(t, "executor")
	entered, releaseGate := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseGate) }) }
	commit := startOwnerTestCall(t, release, func() bool {
		return owner.CommitActive(func() { close(entered); <-releaseGate })
	})
	awaitOwnerSignal(t, entered)
	requested := make(chan struct{})
	mark := startOwnerTestCall(t, release, func() bool {
		close(requested)
		return owner.MarkRegistered()
	})
	awaitOwnerSignal(t, requested)
	select {
	case <-mark.joined:
		t.Error("registration passed the held commit guard")
	case <-owner.Registered():
		t.Error("registration signaled before passing the commit guard")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	if !commit.wait(t) || !mark.wait(t) || !owner.Active() || !owner.Available() {
		t.Error("registered owner did not become available")
	}
	awaitOwnerSignal(t, owner.Registered())
}

func TestSessionOwnerSharedAvailability(t *testing.T) {
	if owner, err := NewSessionOwner("", testOwnerBinding(), time.Minute); err == nil || owner != nil {
		t.Fatal("empty executor ID accepted")
	}
	owner := newTestOwner(t, "executor")
	if owner.ExecutorID() != "executor" || !owner.Active() || owner.Available() {
		t.Fatal("fresh owner has the wrong identity or availability")
	}
	select {
	case <-owner.Registered():
		t.Fatal("fresh owner is already registered")
	case <-owner.Done():
		t.Fatal("fresh owner is already retired")
	default:
	}

	// Concurrent idempotent marks close one shared notification without
	// introducing a second availability authority for registry and transport.
	marks := make([]ownerTestCall, 16)
	for i := range marks {
		marks[i] = startOwnerTestCall(t, nil, owner.MarkRegistered)
	}
	for _, mark := range marks {
		if !mark.wait(t) {
			t.Error("active registration was not idempotent")
		}
	}
	awaitOwnerSignal(t, owner.Registered())
	if !owner.Active() || !owner.Available() {
		t.Fatal("completed registration is unavailable")
	}

	retires := make([]ownerTestCall, 16)
	for i := range retires {
		retires[i] = startOwnerTestCall(t, nil, owner.Retire)
	}
	winners := 0
	for _, retire := range retires {
		if retire.wait(t) {
			winners++
		}
	}
	if winners != 1 || owner.Active() || owner.Available() || owner.MarkRegistered() {
		t.Fatalf("retirement winners=%d; owner did not remain retired", winners)
	}
	awaitOwnerSignal(t, owner.Done())
	awaitOwnerSignal(t, owner.Registered()) // Historical, not current availability.
	replacement := newTestOwner(t, owner.ExecutorID())
	if replacement == owner || replacement.Done() == owner.Done() || replacement.Registered() == owner.Registered() {
		t.Error("replacement reused its predecessor's identity or notifications")
	}
	if !replacement.Active() || replacement.Available() || owner.Active() {
		t.Error("fresh same-ID owner inherited registration or reactivated predecessor")
	}
}

func TestSessionOwnerRegistrationRacesRetirement(t *testing.T) {
	owner := newTestOwner(t, "executor")
	start := make(chan struct{})
	var startOnce sync.Once
	release := func() { startOnce.Do(func() { close(start) }) }
	marks, retires := make([]ownerTestCall, 16), make([]ownerTestCall, 16)
	for i := range marks {
		marks[i] = startOwnerTestCall(t, release, func() bool { <-start; return owner.MarkRegistered() })
		retires[i] = startOwnerTestCall(t, release, func() bool { <-start; return owner.Retire() })
	}
	release()
	registered, retired := 0, 0
	for i := range marks {
		if marks[i].wait(t) {
			registered++
		}
		if retires[i].wait(t) {
			retired++
		}
	}
	if retired != 1 || owner.Active() || owner.Available() || owner.MarkRegistered() {
		t.Fatalf("racing registration revived owner; retirement winners=%d", retired)
	}
	select {
	case <-owner.Registered():
		if registered == 0 {
			t.Error("registration notification has no successful mark")
		}
	default:
		if registered != 0 {
			t.Error("successful mark did not signal registration")
		}
	}
	awaitOwnerSignal(t, owner.Done())
}

func TestSessionOwnerBinding(t *testing.T) {
	binding := testOwnerBinding()
	owner, err := NewSessionOwner("executor", binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	binding.SessionID = "changed-caller-value"
	observed := owner.Binding()
	if observed != testOwnerBinding() {
		t.Fatal("constructor retained mutable binding input")
	}
	observed.Incarnation = "changed-getter-value"
	if owner.Binding() != testOwnerBinding() {
		t.Fatal("getter exposes mutable owner binding")
	}
	for _, invalid := range []controlsession.Binding{{}, {Incarnation: binding.Incarnation, SessionID: "invalid-supplied-session"}} {
		if got, err := NewSessionOwner("executor", invalid, time.Minute); got != nil || err == nil {
			t.Fatal("owner accepted invalid binding")
		}
	}
	owner.Retire()
	awaitOwnerSignal(t, owner.MutationsDrained())
}
