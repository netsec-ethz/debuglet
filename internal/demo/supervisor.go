// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package demo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

// ChildProcess owns a child and its process group until CleanupComplete.
type ChildProcess interface {
	PID() int
	Done() <-chan struct{}
	Wait(context.Context) error
	Stop(context.Context) error
	CleanupComplete() bool
}

type supervisedChild struct {
	process  ChildProcess
	name     string
	daemon   bool
	stopping atomic.Bool
	forced   bool
}

// Supervisor starts local commands, observes unexpected daemon exits and joins
// the children in reverse order. The caller serializes StartChild, Stop and Close.
type Supervisor struct {
	ctx         context.Context
	cancel      context.CancelCauseFunc
	watchCtx    context.Context
	cancelWatch context.CancelFunc
	watchers    sync.WaitGroup
	children    []*supervisedChild
	start       func(ChildSpec) (ChildProcess, error)
}

func NewSupervisor(ctx context.Context) *Supervisor {
	return newSupervisor(ctx, productionDependencies())
}

func newSupervisor(ctx context.Context, deps dependencies) *Supervisor {
	work, cancel := context.WithCancelCause(ctx)
	watch, cancelWatch := context.WithCancel(work)
	return &Supervisor{ctx: work, cancel: cancel, watchCtx: watch, cancelWatch: cancelWatch, start: deps.startChild}
}

func (s *Supervisor) Context() context.Context { return s.ctx }
func (s *Supervisor) Cancel(cause error)       { s.cancel(cause) }

// StartChild tracks even a command which later fails. A daemon exit cancels the
// supervisor context; ordinary command exits belong to the waiting caller.
func (s *Supervisor) StartChild(name string, spec ChildSpec, daemon bool) (ChildProcess, error) {
	child, err := s.start(spec)
	if err != nil {
		return nil, err
	}
	owned := &supervisedChild{process: child, name: name, daemon: daemon}
	s.children = append(s.children, owned)
	if daemon {
		s.watchers.Add(1)
		go func() {
			defer s.watchers.Done()
			select {
			case <-s.watchCtx.Done():
			case <-child.Done():
				if s.watchCtx.Err() == nil && !owned.stopping.Load() {
					s.cancel(fmt.Errorf("%s exited before cleanup: %w", name, errors.Join(errors.New("unexpected child exit"), child.Wait(s.watchCtx))))
				}
			}
		}()
	}
	return child, nil
}

// Healthy also observes an exit whose watcher has not yet been scheduled.
func (s *Supervisor) Healthy() error {
	for _, child := range s.children {
		if child.daemon && !child.stopping.Load() && isDone(child.process.Done()) {
			return fmt.Errorf("%s exited before cleanup", child.name)
		}
	}
	return nil
}

// Quiesce joins exit observers before a frontend begins phased cleanup of its
// other resources. Close also calls it, so cleanup is safe after partial setup.
func (s *Supervisor) Quiesce() {
	s.cancelWatch()
	s.watchers.Wait()
	s.cancel(nil)
}

func (s *Supervisor) stop(ctx context.Context, child *supervisedChild) error {
	child.stopping.Store(true)
	err := child.process.Stop(ctx)
	child.forced = child.forced || errors.Is(err, ErrForcedKill)
	return err
}

// Stop deliberately stops one tracked child without declaring it an unexpected
// daemon exit. The child remains tracked until final cleanup joins its group.
func (s *Supervisor) Stop(ctx context.Context, process ChildProcess) error {
	for _, child := range s.children {
		if child.process == process {
			return s.stop(ctx, child)
		}
	}
	return errors.New("child is not owned by this supervisor")
}

type ProcessCleanup struct {
	Joined      bool
	ForcedKills int
}

func (s *Supervisor) Close(ctx context.Context) (ProcessCleanup, error) {
	s.Quiesce()
	var err error
	var active []*supervisedChild
	for i := len(s.children) - 1; i >= 0; i-- {
		child := s.children[i]
		// Completed CLI invocations must not dilute live daemons' stop budgets.
		if !child.daemon && isDone(child.process.Done()) {
			phase, end := context.WithTimeout(ctx, 250*time.Millisecond)
			stopErr := s.stop(phase, child)
			end()
			if !child.process.CleanupComplete() || child.forced {
				err = errors.Join(err, stopErr)
			}
		} else {
			active = append(active, child)
		}
	}
	for i, child := range active {
		phase, end := cleanupPhase(ctx, len(active)-i)
		err = errors.Join(err, s.stop(phase, child))
		end()
	}
	result := ProcessCleanup{Joined: true}
	for _, child := range s.children {
		if !child.process.CleanupComplete() {
			err = errors.Join(err, s.stop(ctx, child))
		}
		result.Joined = result.Joined && child.process.CleanupComplete()
		if child.forced {
			result.ForcedKills++
		}
	}
	if !result.Joined {
		err = errors.Join(err, errors.New("owned process cleanup incomplete"))
	}
	return result, err
}

// RoleProcess preserves the caller's state layout while sharing config writing,
// process ownership and PID-bound startup readiness across local launchers.
type RoleProcess struct {
	Role                                                     storagecheck.Role
	Directory, Executable, ConfigPath, ReadyPath, ExecutorID string
	Configuration                                            map[string]any
	Stdout, Stderr                                           io.Writer
}

func (s *Supervisor) StartRole(ctx context.Context, role RoleProcess) (ChildProcess, readiness.Record, error) {
	if err := WriteConfig(role.ConfigPath, role.Configuration); err != nil {
		return nil, readiness.Record{}, err
	}
	child, err := s.StartChild(string(role.Role), ChildSpec{Path: role.Executable, Dir: role.Directory,
		Args: []string{"--config", role.ConfigPath, "--ready-file", role.ReadyPath},
		Env:  childEnvironment(role.Directory), Stdout: role.Stdout, Stderr: role.Stderr}, true)
	if err != nil {
		return nil, readiness.Record{}, err
	}
	record, err := awaitReady(ctx, role.ReadyPath, child.PID(), role.ExecutorID)
	return child, record, err
}
