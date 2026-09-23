package memory

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

type phase uint8

const (
	persisting phase = iota
	queued
	cancelPending
	active
	finalizing
	completed
	retired
)

// owner is the single incarnation record used by both backends. All mutable
// fields are guarded by MemoryStorage.mu; done channels publish attempt results.
type owner struct {
	spec         scheduler.Spec
	phase        phase
	ctx          context.Context
	cancel       context.CancelCauseFunc
	cause        error
	admitted     chan struct{}
	admissionErr error
	callbackDone chan struct{}
	completion   scheduler.Completion
	attempt      *finalizationAttempt
}

type finalizer func(context.Context, uuid.UUID) error

// An inspector classifies an absent core owner without altering persisted rows.
// Its lifetime is counted just like persistence, restoration and finalization.
type absentInspector func(context.Context, uuid.UUID, controlsession.Binding) error

type finalizationAttempt struct {
	done     chan struct{}
	err      error
	finalErr error
}

// NewPersistentStorage shares the queue's ownership state with a persistent
// backend. persist returns the spec kept in memory after the successful write;
// finalize only removes the canonical row. Neither runs under the queue lock.
func NewPersistentStorage(persist func(context.Context, scheduler.Spec) (scheduler.Spec, error), finalize func(context.Context, uuid.UUID) error, inspect func(context.Context, uuid.UUID, controlsession.Binding) error, admission scheduler.Admission) (*MemoryStorage, error) {
	m, err := NewStorage(admission)
	if err != nil {
		return nil, err
	}
	m.persist, m.finalize, m.inspect = persist, finalize, inspect
	return m, nil
}

func (m *MemoryStorage) changedLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func newOwner(ctx context.Context, spec scheduler.Spec, state phase) *owner {
	return &owner{spec: spec, phase: state, ctx: context.WithoutCancel(ctx), admitted: make(chan struct{}), callbackDone: make(chan struct{})}
}

func newAttempt() *finalizationAttempt { return &finalizationAttempt{done: make(chan struct{})} }

func (m *MemoryStorage) insert(ctx context.Context, spec scheduler.Spec) error {
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	if m.closed {
		m.mu.Unlock()
		return scheduler.ErrClosed
	}
	if _, exists := m.owners[spec.DebugletID]; exists {
		m.mu.Unlock()
		return fmt.Errorf("debuglet %s already has an admission owner", spec.DebugletID)
	}
	o := newOwner(ctx, spec, queued)
	var commitErr error
	commit := func() {
		if commitErr = ctx.Err(); commitErr != nil {
			return
		}
		m.owners[spec.DebugletID] = o
		if m.persist == nil {
			m.tq.Push(spec)
			close(o.admitted)
		} else {
			o.phase = persisting
			m.busy++
		}
	}
	if err := m.admission.Insert(spec.Binding, commit); err != nil {
		m.mu.Unlock()
		return err
	}
	if commitErr != nil {
		m.mu.Unlock()
		return commitErr
	}
	if m.persist == nil {
		m.mu.Unlock()
		m.notify()
		return nil
	}
	m.mu.Unlock()

	stored, err := m.persist(ctx, spec)
	m.mu.Lock()
	o.admissionErr = err
	if err != nil {
		o.phase = retired
		delete(m.owners, spec.DebugletID)
		if o.attempt != nil {
			close(o.attempt.done) // No accepted owner, and no deletion to perform.
		}
	} else {
		// The reservation predates Shutdown. Successful persistence must still
		// install accepted work; closed only prevents new reservations/dispatch.
		o.spec = stored
		if o.attempt == nil {
			o.phase = queued
			m.tq.Push(stored)
		} else {
			o.phase = cancelPending
			m.busy++ // The already-admitted cancellation owns its deletion.
		}
	}
	close(o.admitted)
	m.busy--
	m.changedLocked()
	a := o.attempt
	startDelete := err == nil && a != nil
	m.mu.Unlock()
	if startDelete {
		go m.deleteQueued(o, a)
	}
	m.notify()
	return err
}

// Restore reserves the database-reading operation, so Shutdown cannot finish
// while a backend is still paging. emit imports already-persisted rows and
// never invokes the persistence hook. Shutdown may stop further import; rows
// left in the canonical database remain recoverable on the next startup.
func (m *MemoryStorage) Restore(ctx context.Context, load func(context.Context, func(scheduler.Spec) error) error) error {
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	if m.closed {
		m.mu.Unlock()
		return scheduler.ErrClosed
	}
	m.busy++
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.busy--; m.changedLocked(); m.mu.Unlock() }()
	return load(ctx, func(spec scheduler.Spec) error {
		m.mu.Lock()
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			return err
		}
		if m.closed {
			m.mu.Unlock()
			return scheduler.ErrClosed
		}
		if _, exists := m.owners[spec.DebugletID]; exists {
			m.mu.Unlock()
			return fmt.Errorf("debuglet %s already has an admission owner", spec.DebugletID)
		}
		o := newOwner(ctx, spec, queued)
		m.owners[spec.DebugletID] = o
		m.tq.Push(spec)
		close(o.admitted)
		m.mu.Unlock()
		m.notify()
		return nil
	})
}

// Inspect reserves one backend-owned read the same way persistence,
// restoration and finalization are reserved: Shutdown joins it before claiming
// quiescence, and a closed core refuses a new read instead of racing database
// closure. Cancelling ctx does not release the reservation; only read
// returning does, so a backend that keeps using its connection past
// cancellation is still joined rather than abandoned.
func (m *MemoryStorage) Inspect(ctx context.Context, read func(context.Context) error) error {
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	if m.closed {
		m.mu.Unlock()
		return scheduler.ErrClosed
	}
	m.busy++
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.busy--; m.changedLocked(); m.mu.Unlock() }()
	return read(ctx)
}

// Cancel signals the matching owner and waits for local cleanup and canonical
// row removal. A caller timeout retains the owner and its uncertain result. It
// compares no binding, so it is the backends' own operation rather than one a
// control session may ask for.
func (m *MemoryStorage) Cancel(ctx context.Context, id uuid.UUID, cause error) (bool, error) {
	return m.requestCancel(ctx, id, cause, false, nil)
}

func (m *MemoryStorage) CancelBound(ctx context.Context, id uuid.UUID, binding controlsession.Binding, cause error) (bool, error) {
	if !binding.Valid() {
		return false, scheduler.ErrBindingMismatch
	}
	return m.requestCancel(ctx, id, cause, false, &binding)
}

func (m *MemoryStorage) requestCancel(ctx context.Context, id uuid.UUID, cause error, queueOnly bool, expected *controlsession.Binding) (bool, error) {
	if cause == nil {
		cause = context.Canceled
	}
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return false, err
	}
	o, found := m.owners[id]
	if !found {
		if m.closed {
			m.mu.Unlock()
			return false, scheduler.ErrClosed
		}
		if expected == nil || m.inspect == nil {
			m.mu.Unlock()
			return false, nil
		}
		// Absence is the cancellation linearization point. A later Insert is not
		// this operation's owner and must never be canceled after SQL inspection.
		m.busy++
		inspect := m.inspect
		m.mu.Unlock()
		defer func() { m.mu.Lock(); m.busy--; m.changedLocked(); m.mu.Unlock() }()
		return false, inspect(ctx, id, *expected)
	}
	// Compare before selecting a cause, creating an attempt, signaling execution
	// or removing a queued entry. Never unlock then invoke unrestricted Cancel.
	if expected != nil && o.spec.Binding != *expected {
		m.mu.Unlock()
		return false, scheduler.ErrBindingMismatch
	}
	if queueOnly && (o.phase == active || o.phase == finalizing || o.phase == completed) {
		if m.closed {
			m.mu.Unlock()
			return false, scheduler.ErrClosed
		}
		m.mu.Unlock()
		return false, fmt.Errorf("debuglet %s is already started", id)
	}
	// A bound caller may rejoin an already completed owner after closure. The
	// stored result is immutable; closure never permits a failed SQL retry.
	if m.closed && expected != nil && o.phase == completed {
		err := o.attempt.err
		m.mu.Unlock()
		return true, err
	}
	// Closing permits joins of existing operations, never new SQL or retries.
	if m.closed && !(o.phase == cancelPending || o.phase == finalizing || o.phase == active || o.phase == persisting && o.attempt != nil) {
		m.mu.Unlock()
		return false, scheduler.ErrClosed
	}
	var startQueued, startFinal bool
	var signal context.CancelCauseFunc
	switch o.phase {
	case persisting:
		if o.attempt == nil {
			o.attempt, o.cause = newAttempt(), cause
		}
	case queued:
		m.tq.Remove(id)
		o.phase, o.cause, o.attempt = cancelPending, cause, newAttempt()
		m.busy++
		startQueued = true
	case active:
		if !m.closed {
			if o.cause == nil {
				o.cause = cause
			}
			signal = o.cancel
			cause = o.cause
		}
	case completed:
		if o.attempt.finalErr != nil {
			o.phase, o.attempt = finalizing, newAttempt()
			m.busy++
			startFinal = true
		}
	}
	a := o.attempt
	m.mu.Unlock()
	if signal != nil {
		signal(cause) // Signal before joining, outside every scheduler lock.
	}
	if startQueued {
		m.notify()
		go m.deleteQueued(o, a)
	} else if startFinal {
		go m.finalizeOwner(o, a)
	}
	select {
	case <-a.done:
		if o.admissionErr != nil {
			return false, nil
		}
		return true, a.err
	case <-ctx.Done():
		return true, ctx.Err()
	}
}

func (m *MemoryStorage) deleteQueued(o *owner, a *finalizationAttempt) {
	err := m.callFinalizer(o)
	m.mu.Lock()
	a.err, a.finalErr = err, err
	if err != nil {
		o.phase, o.cause = queued, nil
		m.tq.Push(o.spec)
	} else {
		o.phase = retired
		close(o.callbackDone) // Queued cancellation owns no executor callback.
		delete(m.owners, o.spec.DebugletID)
	}
	// notify is a nonblocking hint. Publish it before the operation's join
	// signal, while the restored queue state is protected by the same guard.
	m.notify()
	close(a.done)
	m.busy--
	m.changedLocked()
	m.mu.Unlock()
}

func (m *MemoryStorage) callFinalizer(o *owner) error {
	if m.finalize == nil {
		return nil
	}
	// Backend admission may outlast a caller's join. The backend starts the
	// bounded SQL execution context only after obtaining its connection.
	return m.finalize(context.WithoutCancel(o.ctx), o.spec.DebugletID)
}

func (m *MemoryStorage) runOwner(o *owner, callback scheduler.StartFunc) {
	result := callback(o.ctx, o.spec)
	m.mu.Lock()
	o.completion = result
	o.phase = finalizing
	close(o.callbackDone)
	a := o.attempt
	cause := o.cause
	m.changedLocked()
	m.mu.Unlock()
	// Cancel may already have selected its cause but not yet called cancel.
	// Natural callback return must not replace that committed choice.
	o.cancel(cause)
	m.finalizeOwner(o, a)
}

func (m *MemoryStorage) finalizeOwner(o *owner, a *finalizationAttempt) {
	err := m.callFinalizer(o)
	m.mu.Lock()
	a.finalErr = err
	a.err = errors.Join(o.completion.CleanupErr, err)
	o.phase = completed
	if a.err == nil {
		o.phase = retired
		delete(m.owners, o.spec.DebugletID)
	}
	close(a.done)
	m.busy--
	m.changedLocked()
	m.mu.Unlock()
}

func (m *MemoryStorage) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.stop)
	}
	var signals []func()
	for _, o := range m.owners {
		if o.phase == active {
			if o.cause == nil {
				o.cause = context.Canceled
			}
			cause := o.cause
			cancel := o.cancel
			signals = append(signals, func() { cancel(cause) })
		}
	}
	m.mu.Unlock()
	for _, signal := range signals {
		signal()
	}
	for {
		m.mu.Lock()
		if m.busy == 0 && !m.loopRunning {
			var err error
			for _, o := range m.owners {
				if o.phase == completed {
					err = errors.Join(err, o.attempt.err)
				}
			}
			m.mu.Unlock()
			return err
		}
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
