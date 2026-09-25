//go:build linux

package demo

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Child owns one process group and exactly one cmd.Wait invocation. Closing
// done publishes waitErr and also joins os/exec's output-copy goroutines.
type Child struct {
	cmd       *exec.Cmd
	done      chan struct{}
	waitErr   error
	stopMu    sync.Mutex
	stopping  bool
	stopDone  chan struct{}
	stopErr   error
	groupMu   sync.Mutex
	groupGone bool
}

func StartChild(spec ChildSpec) (*Child, error) {
	if !filepath.IsAbs(spec.Path) || !filepath.IsAbs(spec.Dir) {
		return nil, errors.New("demo child requires absolute executable and working directory paths")
	}
	cmd := exec.Command(spec.Path, spec.Args...)
	cmd.Dir = spec.Dir
	// A nil Env would inherit machine configuration. Even the empty whitelist
	// is represented by a nonnil slice.
	cmd.Env = append([]string{}, spec.Env...)
	cmd.Stdout, cmd.Stderr = spec.Stdout, spec.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Bound pipe draining if a dying child left a descendant holding a pipe.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", filepath.Base(spec.Path), err)
	}
	c := &Child{cmd: cmd, done: make(chan struct{}), stopDone: make(chan struct{})}
	go func() {
		c.waitErr = cmd.Wait()
		close(c.done)
	}()
	return c, nil
}

func (c *Child) PID() int              { return c.cmd.Process.Pid }
func (c *Child) Done() <-chan struct{} { return c.done }

func (c *Child) Wait(ctx context.Context) error {
	select {
	case <-c.done:
		return c.waitErr
	default:
	}
	select {
	case <-c.done:
		return c.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop starts teardown once. The first caller owns its bounded controller;
// other callers can join it with their own context. No stop goroutine outlives
// its caller. Done alone describes the direct child, not its process group.
func (c *Child) Stop(ctx context.Context) error {
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	c.stopMu.Lock()
	first := !c.stopping
	c.stopping = true
	c.stopMu.Unlock()
	if first {
		if ctx.Err() != nil {
			// There is no remaining grace budget. Signal synchronously, and
			// let a later caller join the existing reaper and process group.
			c.stopErr = ErrForcedKill
			if err := syscall.Kill(-c.PID(), syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				c.stopErr = errors.Join(c.stopErr, fmt.Errorf("kill child group %d: %w", c.PID(), err))
			}
		} else {
			c.stopErr = c.stop(ctx)
		}
		close(c.stopDone)
		if ctx.Err() != nil {
			return errors.Join(c.stopErr, ctx.Err())
		}
		return c.stopErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-c.stopDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	// A controller can finish at its phase deadline before SIGKILL has been
	// reaped. Join that existing ownership using this caller's remaining budget.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.CleanupComplete() {
			return c.exitResult(c.stopErr)
		}
		select {
		case <-ctx.Done():
			return errors.Join(c.stopErr, ctx.Err())
		case <-ticker.C:
		}
	}
}

// CleanupComplete proves both the controller and direct-child reaper joined,
// and that the entire tracked process group disappeared. Cache observed group
// removal so a future unrelated reuse of this numeric PGID cannot change it.
func (c *Child) CleanupComplete() bool {
	if !isDone(c.stopDone) || !isDone(c.done) {
		return false
	}
	c.groupMu.Lock()
	defer c.groupMu.Unlock()
	if !c.groupGone {
		c.groupGone = errors.Is(syscall.Kill(-c.PID(), 0), syscall.ESRCH)
	}
	return c.groupGone
}

func (c *Child) exitResult(result error) error {
	var exit *exec.ExitError
	if c.waitErr != nil && !(errors.As(c.waitErr, &exit) && expectedStopSignal(exit)) && !errors.Is(result, c.waitErr) {
		return errors.Join(result, c.waitErr)
	}
	return result
}

func (c *Child) stop(ctx context.Context) error {
	deadline, _ := ctx.Deadline()
	var result error
	if err := syscall.Kill(-c.PID(), syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		result = fmt.Errorf("signal child group %d: %w", c.PID(), err)
	}
	forceAt := deadline.Add(-time.Second)
	forced := false
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		reaped := false
		select {
		case <-c.done:
			reaped = true
		default:
		}
		groupErr := syscall.Kill(-c.PID(), 0)
		groupGone := errors.Is(groupErr, syscall.ESRCH)
		if reaped && groupGone {
			// SIGTERM is the requested graceful shutdown for a child that does
			// not install a handler. Wait still reports its original exit status.
			c.groupMu.Lock()
			c.groupGone = true
			c.groupMu.Unlock()
			return c.exitResult(result)
		}
		if !forced && !time.Now().Before(forceAt) {
			if !groupGone {
				if err := syscall.Kill(-c.PID(), syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
					result = errors.Join(result, fmt.Errorf("kill child group %d: %w", c.PID(), err))
				}
				result = errors.Join(result, ErrForcedKill)
			}
			forced = true
		}
		if !time.Now().Before(deadline) {
			return errors.Join(result, fmt.Errorf("child group %d was not reaped before cleanup deadline: %w", c.PID(), context.DeadlineExceeded))
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			if !forced && !groupGone {
				if err := syscall.Kill(-c.PID(), syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
					result = errors.Join(result, fmt.Errorf("kill child group %d: %w", c.PID(), err))
				}
				result = errors.Join(result, ErrForcedKill)
			}
			return errors.Join(result, ctx.Err())
		}
	}
}

func expectedStopSignal(exit *exec.ExitError) bool {
	status, ok := exit.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGTERM
}
