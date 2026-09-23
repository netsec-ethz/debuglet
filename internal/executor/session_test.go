package executor

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// Only Node constructor/disposal invokes this counter. Packet accounting and
// kernel behavior are deliberately not represented by this lifecycle fixture.
type nodeCounter struct {
	ratelimit.PacketCount
	closes atomic.Int32
	err    error
}

func (c *nodeCounter) Type() string { return "lifecycle-fixture" }
func (c *nodeCounter) Close() error { c.closes.Add(1); return c.err }
func nodeTestConfig() *config.ExecutorConfig {
	return &config.ExecutorConfig{
		Identity: config.IdentityConfig{ExecutorID: "node-session-test"}, Dispatcher: config.DispatcherConfig{Addr: "127.0.0.1:1", YamuxAddr: "127.0.0.1:1"},
		TLS: config.TLSConfig{Disable: true}, Tesla: config.TeslaConfig{Delay: 1, ChainLength: 10}, Network: config.NetworkConfig{PacketCounter: "fallback"},
	}
}
func newSessionFixture(t *testing.T) (*Node, *sql.DB, *nodeCounter) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	counter := &nodeCounter{}
	n, err := newNode(nodeTestConfig(), zap.NewNop(), func(*net.Interface, *zap.Logger) (ratelimit.PacketCount, error) { return counter, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := n.Close(); err != nil && !errors.Is(err, ErrNodeBusy) {
			t.Error(err)
		}
	})
	return n, db, counter
}

// scriptedScheduler drives the scheduler side of one session's lifecycle. The
// real scheduler stays reachable through the embedded interface, so a case can
// hold or fail exactly one call and still run the actual one underneath.
type scriptedScheduler struct {
	scheduler.Scheduler
	startLoop func(context.Context) error
	shutdown  func(context.Context) error
}

func (s *scriptedScheduler) StartLoop(ctx context.Context) error {
	if s.startLoop != nil {
		return s.startLoop(ctx)
	}
	return s.Scheduler.StartLoop(ctx)
}

func (s *scriptedScheduler) Shutdown(ctx context.Context) error {
	if s.shutdown != nil {
		return s.shutdown(ctx)
	}
	return s.Scheduler.Shutdown(ctx)
}

func scriptScheduler(s *Session) *scriptedScheduler {
	scripted := &scriptedScheduler{Scheduler: s.storage}
	s.storage = scripted
	return scripted
}

func sessionJoin(t *testing.T, done <-chan struct{}) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(3 * time.Second):
		t.Error("session-owned caller did not join")
		return false
	}
}
func stopAndWaitSession(t *testing.T, s *Session) {
	t.Helper()
	s.Stop(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Wait(ctx); err != nil {
		t.Errorf("session cleanup: %v", err)
	}
}

// A deliberately broken refusal may return a live successor. Retain it for
// bounded harness cleanup, after the tested assertion observes the violation.
func tryRefusedSession(t *testing.T, n *Node, db *sql.DB) error {
	t.Helper()
	s, err := NewSession(n, db)
	if s != nil {
		t.Cleanup(func() { stopAndWaitSession(t, s) })
	}
	return err
}

func TestNodeConstructionRollbackRetainsBothErrors(t *testing.T) {
	initial, release := errors.New("counter construction failed"), errors.New("counter release failed")
	c := &nodeCounter{err: release}
	n, err := newNode(nodeTestConfig(), zap.NewNop(), func(*net.Interface, *zap.Logger) (ratelimit.PacketCount, error) { return c, initial })
	var end *controlsession.EndError
	if n != nil || !errors.Is(err, initial) || !errors.Is(err, release) || !errors.As(err, &end) || end.Kind != controlsession.LocalFailure || c.closes.Load() != 1 {
		t.Fatalf("node=%v error=%v closes=%d", n, err, c.closes.Load())
	}
}

func TestNodeFreshSessionRetainsDaemonResources(t *testing.T) {
	n, db, c := newSessionFixture(t)
	first, err := NewSession(n, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopAndWaitSession(t, first) })
	if err := tryRefusedSession(t, n, db); !errors.Is(err, ErrNodeBusy) {
		t.Fatalf("concurrent successor accepted: %v", err)
	}
	stopAndWaitSession(t, first) // Never-started closure must release reservation.
	second, err := NewSession(n, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopAndWaitSession(t, second) })
	a, b := first.executor, second.executor
	if a.Bidi == b.Bidi || a.scheduler == b.scheduler || a.limiter == b.limiter || a.portManager == b.portManager {
		t.Fatal("successor reused session-local state")
	}
	if a.packetCount != b.packetCount || a.teslaSchedule != b.teslaSchedule || c.closes.Load() != 0 {
		t.Fatal("daemon resources replaced or prematurely closed")
	}
	stopAndWaitSession(t, second)
	var callers sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		callers.Go(func() { results <- n.Close() })
	}
	callers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
	if c.closes.Load() != 1 {
		t.Fatalf("daemon counter closed %d times", c.closes.Load())
	}
	if err := tryRefusedSession(t, n, db); !errors.Is(err, ErrNodeClosed) {
		t.Fatalf("closed node allowed successor: %v", err)
	}
}

func TestSessionSignalsBothDomainsBeforeJoining(t *testing.T) {
	n, db, c := newSessionFixture(t)
	s, err := NewSession(n, db)
	if err != nil {
		t.Fatal(err)
	}
	s.restore = nil // This test isolates lifecycle joins; SQL restore has real tests.
	scripted := scriptScheduler(s)
	listener, loop, listenerCancelled, loopCancelled := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.listen = func(ctx context.Context) error {
		close(listener)
		<-ctx.Done()
		close(listenerCancelled)
		return context.Cause(ctx)
	}
	s.ready = func(context.Context) error { return nil }
	scripted.startLoop = func(ctx context.Context) error {
		close(loop)
		<-ctx.Done()
		close(loopCancelled)
		return context.Cause(ctx)
	}
	transportEntered, storageEntered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	closeTransport, shutdown := s.closeTransport, scripted.Scheduler.Shutdown
	s.closeTransport = func() { close(transportEntered); <-release; closeTransport() }
	scripted.shutdown = func(ctx context.Context) error { close(storageEntered); <-release; return shutdown(ctx) }
	runDone := make(chan struct{})
	var runErr error
	go func() { defer close(runDone); runErr = s.Run(context.Background()) }()
	t.Cleanup(func() { unlock(); s.Stop(nil); sessionJoin(t, runDone); stopAndWaitSession(t, s) })
	if !sessionJoin(t, listener) || !sessionJoin(t, loop) {
		return
	}
	cause := &controlsession.EndError{Kind: controlsession.LeaseExpired, Err: errors.New("fixture lease elapsed")}
	s.Stop(cause)
	for _, ch := range []<-chan struct{}{listenerCancelled, loopCancelled, transportEntered, storageEntered} {
		if !sessionJoin(t, ch) {
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = s.Wait(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait passed unjoined cleanup: %v", err)
	}
	if err := tryRefusedSession(t, n, db); !errors.Is(err, ErrNodeBusy) {
		t.Fatalf("Wait timeout allowed successor: %v", err)
	}
	if err := n.Close(); !errors.Is(err, ErrNodeBusy) || c.closes.Load() != 0 {
		t.Fatalf("busy Close consumed daemon resource: %v count=%d", err, c.closes.Load())
	}
	unlock()
	if !sessionJoin(t, runDone) {
		return
	}
	stopAndWaitSession(t, s)
	if !errors.Is(runErr, cause) || !errors.Is(s.Cause(), cause) {
		t.Fatalf("first loss cause changed: run=%v cause=%v", runErr, s.Cause())
	}
	if err := n.Close(); err != nil || c.closes.Load() != 1 {
		t.Fatalf("post-join Close did not finish disposal: %v count=%d", err, c.closes.Load())
	}
}

func TestSessionFailedCleanupNeverEnablesSuccessor(t *testing.T) {
	n, db, c := newSessionFixture(t)
	s, err := NewSession(n, db)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("scheduler finalization failed")
	scripted := scriptScheduler(s)
	actual := scripted.Scheduler.Shutdown
	scripted.shutdown = func(ctx context.Context) error { return errors.Join(actual(ctx), sentinel) }
	s.Stop(&controlsession.EndError{Kind: controlsession.TransportUnavailable, Err: errors.New("fixture lost")})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Wait(ctx); !errors.Is(err, sentinel) {
		t.Fatalf("cleanup error lost: %v", err)
	}
	if err := tryRefusedSession(t, n, db); !errors.Is(err, ErrNodeBusy) {
		t.Fatalf("failed cleanup enabled successor: %v", err)
	}
	if err := n.Close(); !errors.Is(err, ErrNodeBusy) || c.closes.Load() != 0 {
		t.Fatalf("failed cleanup disposed shared resources: %v count=%d", err, c.closes.Load())
	}
}

func TestNodeSessionConstructionFailureReleasesReservation(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil_transport", true: "partial_transport"}[partial], func(t *testing.T) {
			n, db, c := newSessionFixture(t)
			actual := n.newBidi
			sentinel := errors.New("transport construction failed")
			var acquired *rpc.BidiClient
			n.newBidi = func(opts rpc.BidiOptions, state rpc.ExecutorState) (*rpc.BidiClient, error) {
				if !partial {
					return nil, nil
				}
				var err error
				acquired, err = actual(opts, state)
				if err != nil {
					return nil, err
				}
				return acquired, sentinel
			}
			if s, err := NewSession(n, db); s != nil || err == nil || partial && !errors.Is(err, sentinel) {
				t.Fatalf("invalid constructor output accepted: session=%v err=%v", s, err)
			}
			if acquired != nil {
				select {
				case <-acquired.Lost():
				default:
					t.Error("partial transport was not stopped")
				}
				acquired.Close()
			}
			if c.closes.Load() != 0 {
				t.Fatal("failed session disposed shared daemon counter")
			}
			n.newBidi = actual
			s, err := NewSession(n, db)
			if err != nil {
				t.Fatalf("failed construction leaked reservation: %v", err)
			}
			stopAndWaitSession(t, s)
		})
	}
}

// A caller's bound belongs to the caller alone. An expired one reports that
// the local outcome is unknown, and it never abandons the cleanup worker,
// releases the node reservation or permits database closure underneath SQL: a
// later caller still observes the same local outcome. That distinction is what
// an operator drain reads to decide whether anything may be deleted, upgraded
// or closed.
func TestSessionWaitWithAnExpiredBoundAbandonsNoCleanup(t *testing.T) {
	n, db, _ := newSessionFixture(t)
	s, err := NewSession(n, db)
	if err != nil {
		t.Fatal(err)
	}
	s.Stop(errors.New("operator drain"))
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Wait(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait with an expired bound = %v, want no join", err)
	}
	join, release := context.WithTimeout(context.Background(), 3*time.Second)
	defer release()
	if err := s.Wait(join); err != nil {
		t.Fatalf("the cleanup an expired bound left behind never joined: %v", err)
	}
	// Joining is repeatable and stays the same answer.
	if err := s.Wait(join); err != nil {
		t.Fatalf("a repeated join reported a different outcome: %v", err)
	}
}
