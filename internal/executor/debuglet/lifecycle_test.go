package debuglet

import (
	"context"
	"errors"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"go.uber.org/zap"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
)

type heldRuntimeSocket struct {
	socket.Socket
	entered, release chan struct{}
	calls            atomic.Int32
	err              error
}

func (s *heldRuntimeSocket) Close() error {
	s.calls.Add(1)
	close(s.entered)
	<-s.release
	return s.err
}

func TestDebugletCloseJoinsHeldResource(t *testing.T) {
	reg := &socket.SocketRegistry{}
	held := &heldRuntimeSocket{entered: make(chan struct{}), release: make(chan struct{}), err: errors.New("held close error")}
	if _, err := reg.Add(held); err != nil {
		t.Fatal(err)
	}
	deb := &Debuglet{env: &wasm.WasmEnv{Registry: reg}}
	var release sync.Once
	unblock := func() { release.Do(func() { close(held.release) }) }
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	initDone := make(chan struct{})
	var initErr error
	var firstErr, secondErr error
	go func() { defer close(firstDone); firstErr = deb.Close(context.Background()) }()
	go func() { defer close(secondDone); <-held.entered; secondErr = deb.Close(context.Background()) }()
	t.Cleanup(func() {
		unblock()
		joinRuntimeTest(t, firstDone)
		joinRuntimeTest(t, secondDone)
		joinRuntimeTest(t, initDone)
	})
	go func() { defer close(initDone); <-held.entered; initErr = deb.InitRuntime(context.Background(), nil) }()
	joinRuntimeTest(t, held.entered)
	select {
	case <-firstDone:
		t.Fatal("first Close returned before resource joined")
	default:
	}
	select {
	case <-secondDone:
		t.Fatal("repeat Close returned before resource joined")
	default:
	}
	joinRuntimeTest(t, initDone)
	if !errors.Is(initErr, net.ErrClosed) {
		t.Fatalf("late initialization=%v", initErr)
	}
	unblock()
	joinRuntimeTest(t, firstDone)
	joinRuntimeTest(t, secondDone)
	if !errors.Is(firstErr, held.err) || !errors.Is(secondErr, held.err) {
		t.Fatalf("close results=%v,%v", firstErr, secondErr)
	}
	if held.calls.Load() != 1 {
		t.Fatalf("underlying closes=%d", held.calls.Load())
	}
}

// Observe the initial cancellation check without scheduling assumptions. The
// captured nil result proves cancellation occurred after Write's preflight.
type writerCheckContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *writerCheckContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestChannelWriterCancellation(t *testing.T) {
	cause := errors.New("output canceled")
	t.Run("blocked", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		ch := make(chan []byte)
		checked := &writerCheckContext{Context: ctx, checked: make(chan struct{})}
		writer := &chanWriter{ctx: checked, ch: ch}
		done := make(chan struct{})
		var n int
		var err error
		go func() { defer close(done); n, err = writer.Write([]byte("blocked")) }()
		t.Cleanup(func() {
			cancel(cause)
			select {
			case <-done:
			case <-ch:
			}
			joinRuntimeTest(t, done)
		})
		joinRuntimeTest(t, checked.checked)
		cancel(cause)
		joinRuntimeTest(t, done)
		if n != 0 || !errors.Is(err, cause) {
			t.Fatalf("write=%d,%v", n, err)
		}
	})
	t.Run("pre_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(cause)
		ch := make(chan []byte, 1)
		n, err := (&chanWriter{ctx: ctx, ch: ch}).Write([]byte("not admitted"))
		if n != 0 || !errors.Is(err, cause) || len(ch) != 0 {
			t.Fatalf("write=%d,%v queued=%d", n, err, len(ch))
		}
	})
}

func joinRuntimeTest(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime-owned operation did not join")
	}
}

type lateCompiled struct {
	wazero.CompiledModule
	entered, release chan struct{}
	calls            atomic.Int32
	err              error
}

func (c *lateCompiled) Close(context.Context) error {
	c.calls.Add(1)
	close(c.entered)
	<-c.release
	return c.err
}

func TestLateCompiledCleanupErrorSurvivesFinalClose(t *testing.T) {
	deb := &Debuglet{env: &wasm.WasmEnv{}}
	if err := deb.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	compiled := &lateCompiled{entered: make(chan struct{}), release: make(chan struct{}), err: errors.New("late compiler resource failure")}
	var once sync.Once
	unblock := func() { once.Do(func() { close(compiled.release) }) }
	done := make(chan struct{})
	var got error
	go func() { defer close(done); got = deb.publishCompiled(context.Background(), compiled) }()
	t.Cleanup(func() { unblock(); joinRuntimeTest(t, done) })
	joinRuntimeTest(t, compiled.entered)
	if err := deb.Close(context.Background()); err != nil {
		t.Fatalf("unexpected initial closure failure: %v", err)
	}
	unblock()
	joinRuntimeTest(t, done)
	if !errors.Is(got, net.ErrClosed) || !errors.Is(got, compiled.err) {
		t.Fatalf("late publication=%v", got)
	}
	if err := deb.Close(context.Background()); !errors.Is(err, compiled.err) {
		t.Fatalf("final Close lost late error: %v", err)
	}
	if compiled.calls.Load() != 1 {
		t.Fatalf("compiled closes=%d", compiled.calls.Load())
	}
}

type closeErrorModule struct {
	api.Module
	entered, release chan struct{}
	err              error
	calls            atomic.Int32
}

func (m *closeErrorModule) Close(context.Context) error {
	m.calls.Add(1)
	close(m.entered)
	<-m.release
	return m.err
}

type closeErrorRuntime struct {
	wazero.Runtime
	module api.Module
}

func (r *closeErrorRuntime) InstantiateModule(context.Context, wazero.CompiledModule, wazero.ModuleConfig) (api.Module, error) {
	return r.module, nil
}
func (*closeErrorRuntime) Close(context.Context) error { return nil }

type closeErrorCompiled struct{ wazero.CompiledModule }

func (*closeErrorCompiled) Close(context.Context) error { return nil }

func TestRunModuleCloseErrorReachesFinalCleanup(t *testing.T) {
	module := &closeErrorModule{entered: make(chan struct{}), release: make(chan struct{}), err: errors.New("module resource close failed")}
	deb := &Debuglet{env: &wasm.WasmEnv{Logger: zap.NewNop().Sugar()}, runtime: &closeErrorRuntime{module: module}, compiled: &closeErrorCompiled{}}
	var once sync.Once
	unblock := func() { once.Do(func() { close(module.release) }) }
	done := make(chan struct{})
	var runErr error
	go func() { defer close(done); runErr = deb.Run(context.Background(), make(chan []byte), nil) }()
	t.Cleanup(func() { unblock(); joinRuntimeTest(t, done); _ = deb.Close(context.Background()) })
	joinRuntimeTest(t, module.entered)
	if err := deb.Close(context.Background()); err != nil {
		t.Fatalf("first Close=%v", err)
	}
	unblock()
	joinRuntimeTest(t, done)
	if !errors.Is(runErr, module.err) {
		t.Fatalf("Run=%v", runErr)
	}
	if err := deb.Close(context.Background()); !errors.Is(err, module.err) {
		t.Fatalf("final Close lost module error: %v", err)
	}
	if module.calls.Load() != 1 {
		t.Fatalf("module closes=%d", module.calls.Load())
	}
}
