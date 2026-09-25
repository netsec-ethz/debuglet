package wasm

import (
	"errors"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
)

type closeTagger struct {
	tagger.TaggerInterface
	calls atomic.Int32
	err   error
}

func (t *closeTagger) Close() error { t.calls.Add(1); return t.err }

func TestEnvCloseRejectsLateListenerAndPreservesSibling(t *testing.T) {
	sentinel := errors.New("tagger close failure")
	tag := &closeTagger{err: sentinel}
	env := &WasmEnv{Tagger: tag, Registry: &socket.SocketRegistry{}, ScionConn: socket.NewSCIONConnRegistry(1)}
	if err := env.Close(); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	late, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	sibling, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	if err := env.InstallTCP(late, 0, late.Addr().String()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late install: %v", err)
	}
	if _, err := late.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late listener not closed: %v", err)
	}
	if err := env.Close(); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if tag.calls.Load() != 1 {
		t.Fatalf("tagger closes=%d", tag.calls.Load())
	}
	if err := sibling.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("sibling listener closed: %v", err)
	}
}

type heldLateListener struct {
	pan.ListenConn
	entered, release chan struct{}
	calls            atomic.Int32
	err              error
}

func (l *heldLateListener) Close() error { l.calls.Add(1); close(l.entered); <-l.release; return l.err }

func TestEnvFinalCloseIncludesLateListenerFailure(t *testing.T) {
	env := &WasmEnv{}
	if err := env.Close(); err != nil {
		t.Fatal(err)
	}
	listener := &heldLateListener{entered: make(chan struct{}), release: make(chan struct{}), err: errors.New("late listener close failure")}
	var once sync.Once
	unblock := func() { once.Do(func() { close(listener.release) }) }
	done := make(chan struct{})
	var got error
	go func() { defer close(done); got = env.InstallSCION(listener) }()
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("late listener did not join")
		}
	})
	select {
	case <-listener.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("late listener close not entered")
	}
	if err := env.Close(); err != nil {
		t.Fatalf("initial Close=%v", err)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("late listener did not finish")
	}
	if !errors.Is(got, net.ErrClosed) || !errors.Is(got, listener.err) {
		t.Fatalf("late listener result=%v", got)
	}
	if err := env.Close(); !errors.Is(err, listener.err) {
		t.Fatalf("final Close lost late error: %v", err)
	}
	if listener.calls.Load() != 1 {
		t.Fatalf("listener closes=%d", listener.calls.Load())
	}
}
