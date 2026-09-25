package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

// Session owns local completion. Binding, deadlines and first loss cause exist
// only in executor.Bidi; this type never reconstructs lease authority.
type Session struct {
	node        *Node
	executor    *Executor
	storage     scheduler.Scheduler
	restore     func(context.Context) error
	mu          sync.Mutex
	started     bool
	stopping    bool
	cancel      context.CancelCauseFunc
	runDone     chan struct{}
	cleanupDone chan struct{}
	cleanupErr  error
	// The scheduler is called directly; these three are the transport-side
	// boundaries, this executor's own methods unless a fixture drives them.
	listen         func(context.Context) error
	ready          func(context.Context) error
	closeTransport func()
}

func (s *Session) initialize() error {
	e, err := newExecutor(s.node, s.storage)
	if err != nil {
		return err
	}
	// The transport is this session's own: a partially constructed one is
	// revoked and closed here rather than published with the session.
	bidi, err := s.node.newBidi(s.node.opts, e)
	if err != nil {
		if bidi != nil {
			bidi.Stop(err)
			bidi.Close()
		}
		return err
	}
	if bidi == nil {
		return errors.New("control transport constructor returned nil")
	}
	e.Bidi = bidi
	s.executor = e
	e.session = s
	s.listen, s.ready, s.closeTransport = e.Listen, e.WaitResourcesReady, e.closeTransport
	return nil
}

func (s *Session) Lost() <-chan struct{} { return s.executor.Bidi.Lost() }
func (s *Session) Cause() error          { return s.executor.Bidi.Cause() }

// Stop revokes the transport's eligibility at once and cancels running work,
// then starts both owned cleanup domains; cleanup joins them.
func (s *Session) Stop(cause error) {
	s.executor.Bidi.Stop(cause)
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	cancel := s.cancel
	if !s.started {
		s.started = true // A stopped unused session can never subsequently run.
		close(s.runDone)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel(s.Cause())
	}
	go s.cleanup()
}

func (s *Session) cleanup() {
	storageDone, transportDone := make(chan struct{}), make(chan struct{})
	var storageErr error
	go func() { defer close(storageDone); storageErr = s.storage.Shutdown(context.Background()) }()
	go func() { defer close(transportDone); s.closeTransport() }()
	<-storageDone
	<-transportDone
	<-s.runDone
	s.cleanupErr = storageErr
	if storageErr == nil {
		s.node.release(s)
	}
	close(s.cleanupDone)
}

// Wait bounds only the caller's join. A timeout never abandons the cleanup that
// is running, releases the node reservation, or permits database closure
// underneath SQL.
//
// A nil error is the join itself: local ownership finished and the retained state
// is nobody's any more. Any other outcome, an expired bound included, leaves the
// local outcome unknown, and nothing may be deleted, upgraded or closed on the
// strength of it. Either way what storage holds is this package's ordinary
// disposition of stopped work.
func (s *Session) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.cleanupDone:
		return s.cleanupErr
	}
}

func (s *Session) WaitResourcesReady(ctx context.Context) error {
	return s.executor.WaitResourcesReady(ctx)
}

// Run reports why this session ended; Wait separately reports whether all local
// work joined cleanly. Restore precedes all network and fresh queue execution.
func (s *Session) Run(parent context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return sessionEnd(controlsession.LocalFailure, errors.New("session is already started or stopped"))
	}
	s.started = true
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(parent))
	s.cancel = cancel
	s.mu.Unlock()
	defer close(s.runDone)
	watchStop, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-parent.Done():
			s.Stop(sessionEnd(controlsession.ParentStopped, context.Cause(parent)))
		case <-s.Lost():
			s.Stop(s.Cause())
		case <-watchStop:
		}
	}()
	defer func() { close(watchStop); <-watchDone; cancel(s.Cause()) }()
	if parent.Err() != nil {
		s.Stop(sessionEnd(controlsession.ParentStopped, context.Cause(parent)))
		return s.Cause()
	}
	if s.restore != nil {
		if err := s.restore(ctx); err != nil {
			if parent.Err() != nil {
				s.Stop(sessionEnd(controlsession.ParentStopped, context.Cause(parent)))
			} else {
				s.Stop(sessionEnd(controlsession.LocalFailure, fmt.Errorf("restore storage: %w", err)))
			}
			return s.Cause()
		}
	}
	if ctx.Err() != nil {
		s.Stop(context.Cause(ctx))
		return s.Cause()
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		err := s.listen(ctx)
		s.Stop(sessionEnd(controlsession.TransportUnavailable, err))
	}()
	go func() {
		defer workers.Done()
		if err := s.ready(ctx); err != nil {
			s.Stop(sessionEnd(controlsession.TransportUnavailable, err))
			return
		}
		err := s.storage.StartLoop(ctx)
		s.Stop(sessionEnd(controlsession.LocalFailure, err))
	}()
	workers.Wait()
	return s.Cause()
}
