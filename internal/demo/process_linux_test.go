//go:build linux

package demo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestDemoChildHelper(t *testing.T) {
	mode := os.Getenv("DEBUGLET_CHILD_TEST")
	if mode == "" {
		return
	}
	if mode == "ignore" {
		signal.Ignore(syscall.SIGTERM)
		fmt.Println("ready")
		for {
			<-time.After(time.Hour)
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	fmt.Println("ready")
	<-signals
	if mode == "hold after term" {
		fmt.Println("stopping")
		for {
			<-time.After(time.Hour)
		}
	}
	if mode == "self-kill" {
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		select {}
	}
	os.Exit(0)
}

type readyWriter struct {
	once     sync.Once
	ready    chan struct{}
	termOnce sync.Once
	term     chan struct{}
}

func (w *readyWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "ready") {
		w.once.Do(func() { close(w.ready) })
	}
	if strings.Contains(string(p), "stopping") {
		w.termOnce.Do(func() { close(w.term) })
	}
	return len(p), nil
}

func testChild(t *testing.T, mode string) *Child {
	t.Helper()
	c, _ := testObservedChild(t, mode)
	return c
}

func testObservedChild(t *testing.T, mode string) (*Child, *readyWriter) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	w := &readyWriter{ready: make(chan struct{}), term: make(chan struct{})}
	c, err := StartChild(ChildSpec{Path: exe, Dir: t.TempDir(), Args: []string{"-test.run=^TestDemoChildHelper$"}, Env: []string{"DEBUGLET_CHILD_TEST=" + mode}, Stdout: w, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Stop(ctx); err != nil && !errors.Is(err, ErrForcedKill) {
			// This helper deliberately exits abnormally after receiving TERM.
			// Its regression test inspects the retained error below.
			var exit *exec.ExitError
			if mode == "self-kill" && errors.As(err, &exit) {
				if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGKILL {
					return
				}
			}
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-w.ready:
	case <-c.Done():
		t.Fatalf("helper exited: %v", c.Wait(ctx))
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if pgid, err := syscall.Getpgid(c.PID()); err != nil || pgid != c.PID() {
		t.Fatalf("not an owned process group: %d %v", pgid, err)
	}
	return c, w
}

func TestDemoChildConcurrentStopCancellation(t *testing.T) {
	child, output := testObservedChild(t, "hold after term")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	owner := make(chan error, 1)
	go func() { owner <- child.Stop(ctx) }()
	defer func() {
		cancel()
		if owner != nil {
			<-owner
		}
	}()
	select {
	case <-output.term:
	case <-ctx.Done():
		t.Fatal("stop owner did not deliver TERM")
	}
	waiter, stopWaiting := context.WithCancel(context.Background())
	stopWaiting()
	if err := child.Stop(waiter); !errors.Is(err, context.Canceled) {
		t.Fatalf("concurrent waiter cancellation: %v", err)
	}
	if child.CleanupComplete() {
		t.Fatal("cancelled waiter reported active child cleanup complete")
	}
	if err := <-owner; !errors.Is(err, ErrForcedKill) {
		owner = nil
		t.Fatalf("stop owner lost forced-kill result: %v", err)
	}
	owner = nil
	if !child.CleanupComplete() {
		t.Fatal("stop owner returned before joining its controller, reaper and group")
	}
}

func TestDemoChildOwnership(t *testing.T) {
	child := testChild(t, "graceful")
	sibling := testChild(t, "graceful")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := child.Wait(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait cancellation: %v", err)
	}
	if isDone(child.Done()) {
		t.Fatal("cancelled Wait terminated the child")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := child.Stop(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if !isDone(child.Done()) || child.Wait(ctx) != nil || !child.CleanupComplete() {
		t.Fatal("Stop did not join the child")
	}
	if isDone(sibling.Done()) || syscall.Kill(sibling.PID(), 0) != nil {
		t.Fatal("cleanup touched unrelated sibling")
	}
	if err := child.Stop(ctx); err != nil {
		t.Fatalf("idempotent Stop: %v", err)
	}
}

func TestDemoChildForcedKill(t *testing.T) {
	child := testChild(t, "ignore")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := child.Stop(ctx); !errors.Is(err, ErrForcedKill) {
		t.Fatalf("expected forced-kill distinction: %v", err)
	}
	if !isDone(child.Done()) || !child.CleanupComplete() {
		t.Fatal("forced child was not reaped")
	}
	if err := child.Stop(ctx); !errors.Is(err, ErrForcedKill) {
		t.Fatalf("lost final Stop result: %v", err)
	}
}

func TestDemoChildUnexpectedKill(t *testing.T) {
	// testChild waits until the helper has installed its TERM handler. It
	// kills itself only after Stop sends TERM, before our forced-kill deadline.
	child := testChild(t, "self-kill")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := child.Stop(ctx)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || errors.Is(err, ErrForcedKill) {
		t.Fatalf("unexpected child death was not preserved: %v", err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("lost original SIGKILL exit status: %v", exit)
	}
	if !isDone(child.Done()) || child.Wait(ctx) != exit || !child.CleanupComplete() {
		t.Fatal("Stop did not join and preserve the original exit")
	}
	if next := child.Stop(ctx); next != err {
		t.Fatalf("repeated Stop changed its result: %v; first %v", next, err)
	}
}

func TestDemoChildExpiredStopJoins(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "expired"}[expired], func(t *testing.T) {
			child := testChild(t, "ignore")
			var first context.Context
			if expired {
				var cancel context.CancelFunc
				first, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
			} else {
				var cancel context.CancelFunc
				first, cancel = context.WithCancel(context.Background())
				cancel()
			}
			if err := child.Stop(first); !errors.Is(err, first.Err()) {
				t.Fatalf("first Stop: %v", err)
			}
			// A fresh caller must join actual termination even though the
			// first waiter had no remaining time to observe its outcome.
			join, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := child.Stop(join); !errors.Is(err, ErrForcedKill) {
				t.Fatalf("later join lost final result: %v", err)
			}
			if !isDone(child.Done()) || !child.CleanupComplete() {
				t.Fatal("later Stop returned before reaping")
			}
			if err := syscall.Kill(child.PID(), 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("child remains after join: %v", err)
			}
		})
	}
}
