// Package rpc serves the dispatcher's side of the executor control plane and
// owns one session per connected executor.
//
// A session belongs to a SessionOwner: one local lifetime for one executor ID,
// created once the executor has answered Hello on the reverse connection and
// its enrolled identity has been checked, and never reused. It starts active and
// unregistered, becomes available when registration has completed and its lease
// deadline is set, and is retired once — by a replacement session, by a lease
// that ran out, by the end of its connection or by shutdown. The owner holds the
// authority over its session: its clock is fixed at construction, a peer
// supplies no time, and only a reverse probe answered by that exact session
// renews its lease.
//
// Work runs under a Mutation: one operation admitted on the owner it belongs to
// and counted until it finishes. A setup mutation is trusted control of a
// session that is not yet registered — registration and the confirmation of the
// session's binding run under one. An ordinary mutation is admitted for work on
// a registered, available session: every direct RPC frame an executor sends,
// every stream frame, and every call this dispatcher makes to that executor.
// Either kind can fork a same-owner continuation for local work that has to
// outlive the request which started it.
//
// The credentials of a session live in its offer, published with the owner and
// confirmed by the executor over the direct channel before the owner is marked
// registered. The successive sessions of one executor ID share a lane: the
// current owner and the predecessors whose local work has not drained yet. A
// reconnecting executor's registration waits for those predecessors to drain,
// so the ordinary work of two sessions of one executor never overlaps; the
// replacement's setup work may already exist while it waits.
//
// Completion is separate from cancellation. Retirement cancels the context of
// every admitted mutation and releases none of them; only finishing one releases
// its count, and an owner drains once it has been retired and every mutation
// admitted on it, forks included, has finished. A session's invocation joins
// that drain before it forgets the offer and sweeps the lane, so no work an
// owner started outlives the record of it.
package rpc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
)

const (
	sessionActive uint32 = 1 << iota
	sessionRegistered
)

// SessionOwner identifies one local callback-session lifetime. It must not be
// copied or reused after retirement. It is not a wire identity or credential.
type SessionOwner struct {
	executorID       string
	binding          controlsession.Binding
	mu               sync.Mutex
	state            atomic.Uint32
	registered       chan struct{}
	done             chan struct{}
	mutations        uint64 // all live/finishing ordinary and setup references; mu
	mutationsDrained chan struct{}
	lease            controlsession.LeaseTiming
	deadline         time.Time        // receiver-local monotonic deadline; mu
	sequence         uint64           // last committed renewal; mu
	now              func() time.Time // construction-fixed clock
}

// NewSessionOwner returns a fresh active, not-yet-registered owner.
func NewSessionOwner(executorID string, binding controlsession.Binding, duration time.Duration) (*SessionOwner, error) {
	return NewSessionOwnerWithClock(executorID, binding, duration, time.Now)
}

// NewSessionOwnerWithClock fixes a receiver-local clock at construction.
// Peers never supply time, and changing registry observations cannot renew it.
func NewSessionOwnerWithClock(executorID string, binding controlsession.Binding, duration time.Duration, now func() time.Time) (*SessionOwner, error) {
	if now == nil {
		return nil, errors.New("control session requires a clock")
	}
	lease, err := controlsession.NewLeaseTiming(duration)
	if err != nil {
		return nil, err
	}
	if executorID == "" {
		return nil, errors.New("executor session requires an ID")
	}
	if !binding.Valid() {
		return nil, errors.New("executor session requires a valid binding")
	}
	s := &SessionOwner{
		executorID: executorID,
		lease:      lease, now: now,
		binding:          binding,
		registered:       make(chan struct{}),
		done:             make(chan struct{}),
		mutationsDrained: make(chan struct{}),
	}
	s.state.Store(sessionActive)
	return s, nil
}

func (s *SessionOwner) ExecutorID() string              { return s.executorID }
func (s *SessionOwner) Binding() controlsession.Binding { return s.binding }

// MutationsDrained closes once this owner is retired and every mutation admitted
// on it, forks included, has finished. A waiter's timeout releases no ownership.
// It is a local drain, neither a remote one nor the session transport's cleanup.
// Never wait on it while holding a mutation of the same owner.
func (s *SessionOwner) MutationsDrained() <-chan struct{} { return s.mutationsDrained }

// Active observes liveness without acquiring the commit guard. The observation
// does not authorize a subsequent publication; use CommitActive for that.
func (s *SessionOwner) Active() bool { return s.state.Load()&sessionActive != 0 }

// Available is the shared transport/registry observation of active registration.
// A returned client or snapshot can still be retired after this observation.
func (s *SessionOwner) Available() bool {
	if s.state.Load()&(sessionActive|sessionRegistered) != sessionActive|sessionRegistered {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.availableLocked()
}

// Registered signals successful registration callback completion. It remains
// closed after later retirement, so current users must also check Available.
func (s *SessionOwner) Registered() <-chan struct{} { return s.registered }

// Done signals retirement, not completion of callbacks or resource cleanup.
func (s *SessionOwner) Done() <-chan struct{} { return s.done }

// CommitActive serializes a bounded in-memory commit with retirement. The caller
// must already hold its containing map lock. The callback must not acquire map
// locks, perform I/O, invoke external callbacks, or wait for workers.
func (s *SessionOwner) CommitActive(commit func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Load()&sessionActive == 0 {
		return false
	}
	commit()
	return true
}

// MarkRegistered is called after Connected returns successfully, outside map
// locks. Repeated calls succeed while the owner is active; retirement is final.
func (s *SessionOwner) MarkRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state.Load()
	if state&sessionActive == 0 {
		return false
	}
	if state&sessionRegistered != 0 {
		return s.availableLocked()
	}
	if state&sessionRegistered == 0 {
		s.deadline = s.now().Add(s.lease.Duration)
		s.state.Store(state | sessionRegistered)
		close(s.registered)
	}
	return true
}

// Retire permanently revokes this owner and signals Done once. It invokes no
// cancellation hooks or resource cleanup; their lifetime owner must join them.
func (s *SessionOwner) Retire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retireLocked()
}

func (s *SessionOwner) retireLocked() bool {
	state := s.state.Load()
	if state&sessionActive == 0 {
		return false
	}
	s.state.Store(state &^ sessionActive)
	close(s.done)
	if s.mutations == 0 {
		close(s.mutationsDrained)
	}
	return true
}

// availableLocked is the authority check; delayed expiry scans cannot extend it.
func (s *SessionOwner) availableLocked() bool {
	return s.state.Load()&(sessionActive|sessionRegistered) == sessionActive|sessionRegistered && s.now().Before(s.deadline)
}

// CommitLease is called only after a successful exact-session reverse probe.
// The caller holds its containing map guard and checks current owner identity.
// A duplicate, late result or retired owner can never extend its deadline.
func (s *SessionOwner) CommitLease(sequence uint64) bool {
	return s.commitLease(context.Background(), sequence)
}

func (s *SessionOwner) commitLease(ctx context.Context, sequence uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if ctx.Err() != nil || sequence == 0 || sequence <= s.sequence || s.state.Load()&(sessionActive|sessionRegistered) != sessionActive|sessionRegistered || !now.Before(s.deadline) {
		return false
	}
	s.sequence, s.deadline = sequence, now.Add(s.lease.Duration)
	return true
}

// ExpireLease rechecks the deadline and retires under the same guard renewal
// uses, so neither can overtake the other. Its caller checks exact registry
// ownership; transport removal and cleanup follow outside that registry guard.
// An owner that never registered has no lease to expire and is not retired here:
// it ends with its connection, with a replacement, or with shutdown.
func (s *SessionOwner) ExpireLease() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Load()&(sessionActive|sessionRegistered) != sessionActive|sessionRegistered || s.now().Before(s.deadline) {
		return false
	}
	return s.retireLocked()
}
