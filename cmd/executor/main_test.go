package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"go.uber.org/zap"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSCIONEnvironmentConfiguration(t *testing.T) {
	t.Run("disabled skips loader and setter", func(t *testing.T) {
		err := configureSCIONEnvironment(true, func() (string, error) { t.Fatal("loader invoked"); return "", nil }, func(string, string) error { t.Fatal("setter invoked"); return nil })
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ordinary mode loads and sets", func(t *testing.T) {
		loaded := false
		set := false
		err := configureSCIONEnvironment(false, func() (string, error) { loaded = true; return "127.0.0.1:30255", nil }, func(key, value string) error {
			if !loaded || key != "SCION_DAEMON_ADDRESS" || value != "127.0.0.1:30255" {
				t.Fatalf("setter %q %q loaded=%v", key, value, loaded)
			}
			set = true
			return nil
		})
		if err != nil || !set {
			t.Fatalf("configuration: set=%v err=%v", set, err)
		}
	})
	t.Run("loader error is returned", func(t *testing.T) {
		sentinel := errors.New("load failed")
		err := configureSCIONEnvironment(false, func() (string, error) { return "", sentinel }, func(string, string) error { t.Fatal("setter after failed load"); return nil })
		if !errors.Is(err, sentinel) {
			t.Fatalf("error: %v", err)
		}
	})
}

// A database without a supported schema must fail before the executor starts
// either the network session or a readiness record.
func TestExecutorRestoreFailure(t *testing.T) {
	for _, demo := range []bool{false, true} {
		t.Run(fmt.Sprintf("demo=%t", demo), func(t *testing.T) { testExecutorRestoreFailure(t, demo) })
	}
}

func testExecutorRestoreFailure(t *testing.T, demo bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lis, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready.json")
	cfg := &config.ExecutorConfig{
		Identity:   config.IdentityConfig{ExecutorID: "restore-test"},
		Dispatcher: config.DispatcherConfig{Addr: lis.Addr().String(), YamuxAddr: lis.Addr().String()},
		TLS:        config.TLSConfig{Disable: true},
		Network:    config.NetworkConfig{PacketCounter: "fallback", DisableSCIONEnvironment: true},
		Tesla:      config.TeslaConfig{Delay: 1, ChainLength: 10},
		Database:   config.DatabaseConfig{Path: filepath.Join(dir, "empty.db")},
	}
	readyArgument := ""
	if demo {
		readyArgument = readyPath
	}
	err = runExecutor(ctx, cfg, readyArgument, zap.NewNop())
	if !errors.Is(err, storagecheck.ErrAbsent) {
		t.Fatalf("missing storage: %v", err)
	}
	if _, err := os.Lstat(readyPath); !os.IsNotExist(err) {
		t.Fatalf("failed startup published readiness: %v", err)
	}
	lis.SetDeadline(time.Now())
	conn, err := lis.Accept()
	if conn != nil {
		conn.Close()
		t.Fatal("network session started before restoration succeeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("expected no pending connection: %v", err)
	}
}

// These command-owner fixtures exercise caller joins/readiness/retry decisions.
// Real connection, SQLite and guest boundaries are covered in executor tests.
type commandSession struct {
	mu    sync.Mutex
	cause error
	lost  chan struct{}
	once  sync.Once
	run   func(context.Context) error
	wait  func(context.Context) error
	ready func(context.Context) error
}

func newCommandSession() *commandSession {
	s := &commandSession{lost: make(chan struct{})}
	s.run = func(ctx context.Context) error {
		select {
		case <-s.lost:
		case <-ctx.Done():
			s.Stop(&controlsession.EndError{Kind: controlsession.ParentStopped, Err: ctx.Err()})
		}
		return s.Cause()
	}
	s.wait = func(context.Context) error { return nil }
	s.ready = func(context.Context) error { return nil }
	return s
}
func (s *commandSession) Run(ctx context.Context) error                { return s.run(ctx) }
func (s *commandSession) Wait(ctx context.Context) error               { return s.wait(ctx) }
func (s *commandSession) WaitResourcesReady(ctx context.Context) error { return s.ready(ctx) }
func (s *commandSession) Lost() <-chan struct{}                        { return s.lost }
func (s *commandSession) Cause() error                                 { s.mu.Lock(); defer s.mu.Unlock(); return s.cause }
func (s *commandSession) Stop(err error) {
	s.once.Do(func() { s.mu.Lock(); s.cause = err; s.mu.Unlock(); close(s.lost) })
}

func commandJoin(t *testing.T, done <-chan struct{}) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(7 * time.Second):
		t.Error("command caller did not join")
		return false
	}
}

func TestExecutorReconnectWaitsForActualCallerAndReadinessRemoval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "ready.json")
	first, second := newCommandSession(), newCommandSession()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unlock := func() { releaseOnce.Do(func() { close(release) }) }
	first.run = func(context.Context) error { close(entered); <-first.lost; <-release; return first.Cause() }
	first.wait = func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	created := make(chan int, 2)
	calls := 0
	closedNode, closedDB := false, false
	services := nodeServices{
		newSession: func() (executorSession, error) {
			calls++
			created <- calls
			if calls == 1 {
				return first, nil
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("old readiness survived into successor: %v", err)
			}
			cancel()
			return second, nil
		},
		wait:      func(context.Context, time.Duration) error { return nil },
		closeNode: func() error { closedNode = true; return nil },
		closeStorage: func() error {
			if !closedNode {
				t.Error("database closed before node disposal")
			}
			closedDB = true
			return nil
		},
	}
	done := make(chan struct{})
	var result error
	go func() { defer close(done); result = serveNode(ctx, path, "command-test", services) }()
	t.Cleanup(func() { unlock(); cancel(); commandJoin(t, done) })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("session did not enter")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness not published")
		}
		time.Sleep(time.Millisecond)
	}
	<-created
	first.Stop(&controlsession.EndError{Kind: controlsession.TransportUnavailable, Err: errors.New("connection lost")})
	select {
	case n := <-created:
		t.Errorf("successor %d constructed before caller join", n)
	case <-time.After(30 * time.Millisecond):
	}
	unlock()
	if !commandJoin(t, done) {
		return
	}
	if result != nil || calls != 2 || !closedDB {
		t.Fatalf("result=%v sessions=%d closed=%v", result, calls, closedDB)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("readiness retained: %v", err)
	}
}

func TestExecutorCleanupFailureRetainsSharedResources(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sentinel := errors.New("owned cleanup failed")
	s := newCommandSession()
	s.wait = func(context.Context) error { return sentinel }
	s.Stop(&controlsession.EndError{Kind: controlsession.TransportUnavailable, Err: errors.New("connection lost")})
	calls := 0
	err := serveNode(ctx, "", "cleanup-test", nodeServices{
		newSession:   func() (executorSession, error) { calls++; return s, nil },
		wait:         func(context.Context, time.Duration) error { t.Error("retry after cleanup failure"); return nil },
		closeNode:    func() error { t.Error("node closed despite failed cleanup"); return nil },
		closeStorage: func() error { t.Error("database closed despite failed cleanup"); return nil },
	})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("result=%v calls=%d", err, calls)
	}
}

func TestExecutorLocalFailureDoesNotReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sentinel := errors.New("local startup failed")
	s := newCommandSession()
	s.Stop(&controlsession.EndError{Kind: controlsession.LocalFailure, Err: sentinel})
	closed := false
	err := serveNode(ctx, "", "local-test", nodeServices{
		newSession:   func() (executorSession, error) { return s, nil },
		wait:         func(context.Context, time.Duration) error { t.Error("local failure retried"); return nil },
		closeNode:    func() error { return nil },
		closeStorage: func() error { closed = true; return nil },
	})
	if !errors.Is(err, sentinel) || !closed {
		t.Fatalf("result=%v closed=%v", err, closed)
	}
}

func TestExecutorParentStopSignalsBeforeRunJoin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := newCommandSession()
	entered, done := make(chan struct{}), make(chan struct{})
	s.run = func(context.Context) error { close(entered); <-s.lost; return s.Cause() }
	var end, cleanup error
	go func() { defer close(done); end, cleanup, _ = serveSession(ctx, "", "stop-test", s) }()
	t.Cleanup(func() { cancel(); s.Stop(context.Canceled); commandJoin(t, done) })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Run caller not entered")
	}
	cancel()
	if !commandJoin(t, done) {
		return
	}
	var typed *controlsession.EndError
	if cleanup != nil || !errors.As(end, &typed) || typed.Kind != controlsession.ParentStopped {
		t.Fatalf("end=%v cleanup=%v", end, cleanup)
	}
}

func TestExecutorReadinessRemovalFailureStopsReconnect(t *testing.T) {
	for _, parentStop := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent_stop=%t", parentStop), func(t *testing.T) { testExecutorReadinessRemovalFailure(t, parentStop) })
	}
}

func testExecutorReadinessRemovalFailure(t *testing.T, parentStop bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "ready.json")
	s := newCommandSession()
	calls, closedDB := 0, false
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		result = serveNode(ctx, path, "removal-test", nodeServices{
			newSession: func() (executorSession, error) { calls++; return s, nil },
			wait: func(context.Context, time.Duration) error {
				t.Error("readiness removal failure allowed retry")
				return errors.New("unexpected retry")
			},
			closeNode: func() error { return nil }, closeStorage: func() error { closedDB = true; return nil },
		})
	}()
	t.Cleanup(func() { cancel(); s.Stop(nil); commandJoin(t, done) })
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness not published")
		}
		time.Sleep(time.Millisecond)
	}
	// Replace only this test's owned record with a nonempty directory. The actual
	// removal syscall must fail and must preserve the child, without a fake error.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(path, "owned-child")
	if err := os.WriteFile(child, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if parentStop {
		cancel()
	} else {
		s.Stop(&controlsession.EndError{Kind: controlsession.TransportUnavailable, Err: errors.New("fixture lost")})
	}
	if !commandJoin(t, done) {
		return
	}
	var end *controlsession.EndError
	if !errors.As(result, &end) || end.Kind != controlsession.LocalFailure || !strings.Contains(result.Error(), "remove executor readiness") || calls != 1 || !closedDB {
		t.Fatalf("result=%v calls=%d closedDB=%v", result, calls, closedDB)
	}
	if data, err := os.ReadFile(child); err != nil || string(data) != "preserve" {
		t.Fatalf("readiness cleanup altered child: %q %v", data, err)
	}
}
