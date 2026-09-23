package rpc

import (
	"context"
	"errors"
)

var (
	ErrSessionUnavailable = errors.New("control session is unavailable")
	ErrSessionRetired     = errors.New("control session is retired")
	ErrMutationFinished   = errors.New("control mutation is finished")
)

// Mutation owns one dispatcher-local operation or continuation. It is not an
// acknowledgement of remote execution, and must not be copied. A setup mutation
// never authorizes an ordinary handler. The work and its owned helpers must
// finish before Finish; cancellation alone releases no admission.
type Mutation struct {
	owner        *SessionOwner
	setup        bool
	ctx          context.Context
	cancel       context.CancelCauseFunc
	watcherDone  chan struct{}
	finishedDone chan struct{}
	finished     bool // protected by owner.mu; true as soon as Finish begins
}

func (m *Mutation) Owner() *SessionOwner     { return m.owner }
func (m *Mutation) Context() context.Context { return m.ctx }
func (m *Mutation) IsSetup() bool            { return m.setup }

// Live reports ownership of this mutation, independent of session availability
// or context cancellation. It becomes false before Finish releases its count.
func (m *Mutation) Live() bool {
	m.owner.mu.Lock()
	defer m.owner.mu.Unlock()
	return !m.finished
}

// AdmitMutation requires registered availability. Callers obtain the real
// owner from the transport/registry; this primitive does not resolve identities.
func (s *SessionOwner) AdmitMutation(ctx context.Context) (*Mutation, error) {
	return s.admit(ctx, false)
}

// AdmitSetup is trusted control of a session that is not yet registered, not
// ordinary admission. The transport must first check, under its map lock, that
// this owner is still the current one for its executor ID.
func (s *SessionOwner) AdmitSetup(ctx context.Context) (*Mutation, error) {
	return s.admit(ctx, true)
}

func (s *SessionOwner) admit(ctx context.Context, setup bool) (*Mutation, error) {
	if ctx == nil {
		return nil, errors.New("control mutation requires a context")
	}
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	state := s.state.Load()
	if state&sessionActive == 0 {
		s.mu.Unlock()
		return nil, ErrSessionRetired
	}
	if !setup && !s.availableLocked() {
		s.mu.Unlock()
		return nil, ErrSessionUnavailable
	}
	m := s.reserveMutationLocked(setup)
	s.mu.Unlock()
	m.start(ctx)
	return m, nil
}

// Fork admits a same-owner continuation of a live mutation. Retirement refuses a
// fresh admission but discards no local cleanup already admitted. The caller
// chooses the child's context: nothing is detached and no deadline is added
// implicitly, and passing the parent's Context couples the two lives.
func (m *Mutation) Fork(ctx context.Context) (*Mutation, error) {
	if ctx == nil {
		return nil, errors.New("control mutation requires a context")
	}
	s := m.owner
	s.mu.Lock()
	if m.finished {
		s.mu.Unlock()
		return nil, ErrMutationFinished
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	child := s.reserveMutationLocked(m.setup)
	s.mu.Unlock()
	child.start(ctx)
	return child, nil
}

func (s *SessionOwner) reserveMutationLocked(setup bool) *Mutation {
	s.mutations++
	return &Mutation{owner: s, setup: setup, watcherDone: make(chan struct{}), finishedDone: make(chan struct{})}
}

// start runs only after reservation and outside the owner guard. A retirement
// between reservation and watcher startup is kept by the closed Done channel,
// and the counted mutation cannot drain until this watcher joins.
func (m *Mutation) start(ctx context.Context) {
	m.ctx, m.cancel = context.WithCancelCause(ctx)
	go func() {
		defer close(m.watcherDone)
		select {
		case <-m.owner.Done():
			m.cancel(ErrSessionRetired)
		case <-m.ctx.Done():
		}
	}()
}

// Finish is idempotent, and concurrent callers join the same completion. It must
// run outside all map/owner locks and after this mutation's local work and
// consumer-owned helpers finish. It does not wait for children: each of them is
// counted separately and holds the owner's drain open until it finishes itself.
func (m *Mutation) Finish() {
	s := m.owner
	s.mu.Lock()
	if m.finished {
		s.mu.Unlock()
		<-m.finishedDone
		return
	}
	m.finished = true
	s.mu.Unlock()

	m.cancel(context.Canceled)
	<-m.watcherDone

	s.mu.Lock()
	s.mutations--
	close(m.finishedDone)
	if s.mutations == 0 && s.state.Load()&sessionActive == 0 {
		close(s.mutationsDrained)
	}
	s.mu.Unlock()
}
