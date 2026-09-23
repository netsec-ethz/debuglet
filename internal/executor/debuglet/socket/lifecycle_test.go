package socket

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
)

type lifecycleSocket struct {
	count   atomic.Int32
	closeFn func() error
}

func (*lifecycleSocket) Type() SocketType            { return SocketTypeTCP }
func (*lifecycleSocket) Read([]byte) (int, error)    { return 0, io.EOF }
func (*lifecycleSocket) Write(b []byte) (int, error) { return len(b), nil }
func (*lifecycleSocket) Addr() string                { return "127.0.0.1" }
func (*lifecycleSocket) RemoteAddr() string          { return "127.0.0.1:1" }
func (s *lifecycleSocket) Close() error {
	s.count.Add(1)
	if s.closeFn != nil {
		return s.closeFn()
	}
	return nil
}

func lifecycleWait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("owned operation did not join")
		var zero T
		return zero
	}
}

type closeResult struct {
	done chan struct{}
	err  error
}

func closeAsync(fn func() error) *closeResult {
	result := &closeResult{done: make(chan struct{})}
	go func() { defer close(result.done); result.err = fn() }()
	return result
}
func (r *closeResult) wait(t *testing.T) error {
	t.Helper()
	if r == nil {
		return nil
	}
	lifecycleWait(t, r.done)
	return r.err
}

func TestRegistryCloseJoinsAndRejectsLateAdmission(t *testing.T) {
	reg := &SocketRegistry{}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	sentinel := errors.New("close failed")
	held := &lifecycleSocket{closeFn: func() error { close(entered); <-release; return sentinel }}
	handle, err := reg.Add(held)
	if err != nil {
		t.Fatal(err)
	}
	all := closeAsync(reg.CloseAll)
	calls := []*closeResult{all}
	t.Cleanup(func() {
		unblock()
		for _, call := range calls {
			call.wait(t)
		}
	})
	lifecycleWait(t, entered)
	one := closeAsync(func() error { return reg.Close(handle) })
	calls = append(calls, one)
	repeat := closeAsync(reg.CloseAll)
	calls = append(calls, repeat)
	// Separate observers let failure teardown release the held socket even if
	// an implementation incorrectly invokes external Close under its mutex.
	get := closeAsync(func() error { _, err := reg.Get(handle); return err })
	calls = append(calls, get)
	if err := get.wait(t); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("detached handle: %v", err)
	}
	late := &lifecycleSocket{}
	var lateHandle int32
	add := closeAsync(func() error { var err error; lateHandle, err = reg.Add(late); return err })
	calls = append(calls, add)
	if err := add.wait(t); lateHandle != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late Add=%d,%v", lateHandle, err)
	}
	if late.count.Load() != 1 {
		t.Fatal("late socket not closed once")
	}
	for _, call := range []*closeResult{one, repeat, all} {
		select {
		case <-call.done:
			t.Fatalf("close returned before held callback: %v", call.err)
		default:
		}
	}
	unblock()
	for _, call := range []*closeResult{one, repeat, all} {
		if err := call.wait(t); !errors.Is(err, sentinel) {
			t.Errorf("lost close error: %v", err)
		}
	}
	if held.count.Load() != 1 {
		t.Fatal("underlying socket closed more than once")
	}
	if err := reg.CloseAll(); !errors.Is(err, sentinel) {
		t.Fatalf("repeated result: %v", err)
	}
}

func TestRegistryConcurrentCloseAndSibling(t *testing.T) {
	reg, sibling := &SocketRegistry{}, &SocketRegistry{}
	socket, other := &lifecycleSocket{}, &lifecycleSocket{}
	h, err := reg.Add(socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sibling.Add(other); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = reg.Close(h); _ = reg.CloseAll() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	lifecycleWait(t, done)
	if socket.count.Load() != 1 || other.count.Load() != 0 {
		t.Fatal("wrong socket ownership")
	}
	if _, err := sibling.Get(0); err != nil {
		t.Fatal(err)
	}
	if err := sibling.CloseAll(); err != nil {
		t.Fatal(err)
	}
}

type localSCIONConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *localSCIONConn) Close() error                                { c.closes.Add(1); return c.Conn.Close() }
func (*localSCIONConn) SetPolicy(pan.Policy)                          {}
func (c *localSCIONConn) WriteVia(_ *pan.Path, b []byte) (int, error) { return c.Write(b) }
func (c *localSCIONConn) ReadVia(b []byte) (int, *pan.Path, error) {
	n, e := c.Read(b)
	return n, nil, e
}
func (*localSCIONConn) GetPath() *pan.Path { return nil }

func TestSCIONRegistryJoinsLateLocalDial(t *testing.T) {
	reg := NewSCIONConnRegistry(1)
	local, peer := net.Pipe()
	defer peer.Close()
	conn := &localSCIONConn{Conn: local}
	var iface pan.Conn = conn
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	canceled := make(chan struct{})
	reg.dial = func(ctx context.Context, _ string, _ *zap.SugaredLogger, _ tagger.TaggerInterface) (*SCIONConn, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return &SCIONConn{Conn: &iface}, nil // successful late dial, despite cancellation
	}
	dialCtx, cancelDial := context.WithCancel(context.Background())
	dialCall := closeAsync(func() error {
		_, err := reg.GetOrDial(dialCtx, "local-fixture", zap.NewNop().Sugar(), nil)
		return err
	})
	var closeCall *closeResult
	t.Cleanup(func() { cancelDial(); unblock(); _ = local.Close(); dialCall.wait(t); closeCall.wait(t) })
	lifecycleWait(t, entered)
	closeCall = closeAsync(reg.CloseAll)
	lifecycleWait(t, canceled)
	if _, err := reg.GetOrDial(context.Background(), "other", nil, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late admission: %v", err)
	}
	select {
	case <-closeCall.done:
		t.Fatalf("close did not join dial: %v", closeCall.err)
	default:
	}
	unblock()
	err := dialCall.wait(t)
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("late dial: %v", err)
	}
	if err := closeCall.wait(t); err != nil {
		t.Error(err)
	}
	if conn.closes.Load() != 1 {
		t.Fatalf("SCION connection closes=%d", conn.closes.Load())
	}
	if err := reg.CloseAll(); err != nil {
		t.Fatal(err)
	}
}

type failedLocalSCIONConn struct {
	pan.Conn
	closeFn func() error
	calls   atomic.Int32
}

func (c *failedLocalSCIONConn) Close() error { c.calls.Add(1); return c.closeFn() }

func TestSCIONFailedDialRetainsCleanupError(t *testing.T) {
	reg := NewSCIONConnRegistry(1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	dialErr, closeErr := errors.New("dial failed after acquiring resource"), errors.New("failed dial close error")
	conn := &failedLocalSCIONConn{closeFn: func() error { close(entered); <-release; return closeErr }}
	var iface pan.Conn = conn
	reg.dial = func(context.Context, string, *zap.SugaredLogger, tagger.TaggerInterface) (*SCIONConn, error) {
		return &SCIONConn{Conn: &iface}, dialErr
	}
	call := closeAsync(func() error { _, err := reg.GetOrDial(context.Background(), "local-failure", nil, nil); return err })
	t.Cleanup(func() { unblock(); call.wait(t); _ = reg.CloseAll() })
	lifecycleWait(t, entered)
	if err := reg.CloseAll(); err != nil {
		t.Fatalf("initial snapshot=%v", err)
	}
	unblock()
	if err := call.wait(t); !errors.Is(err, dialErr) || !errors.Is(err, closeErr) {
		t.Fatalf("failed dial=%v", err)
	}
	if err := reg.CloseAll(); !errors.Is(err, closeErr) || errors.Is(err, dialErr) {
		t.Fatalf("final cleanup=%v", err)
	}
	if conn.calls.Load() != 1 {
		t.Fatalf("connection closes=%d", conn.calls.Load())
	}
}
