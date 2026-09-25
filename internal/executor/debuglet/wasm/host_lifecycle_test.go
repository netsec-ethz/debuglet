package wasm

import (
	"context"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/fallback"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"go.uber.org/zap"
)

// testPolicy is the local profile applied to one run: the documented defaults
// plus the local-target switch these fixtures need, because loopback is denied
// until an operator says otherwise.
func testPolicy(t *testing.T, run netpolicy.Run) *netpolicy.Policy {
	t.Helper()
	operator, err := netpolicy.Parse(localSpec())
	if err != nil {
		t.Fatalf("netpolicy.Parse: %v", err)
	}
	return netpolicy.New(operator, run)
}

func hostTrap(fn func()) (err error) {
	defer func() {
		if v := recover(); v != nil {
			var ok bool
			err, ok = v.(error)
			if !ok {
				err = fmt.Errorf("panic: %v", v)
			}
		}
	}()
	fn()
	return nil
}

func TestHostConnectClosesRejectedConnection(t *testing.T) {
	for _, phase := range []string{"missing_limit", "constructor_failure", "closed_registry"} {
		t.Run(phase, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			var peerErr error
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					peerErr = err
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, err := conn.Read(make([]byte, 1))
				if n != 0 || !errors.Is(err, io.EOF) {
					peerErr = fmt.Errorf("raw/attached socket remained open: %d,%v", n, err)
				}
			}()
			t.Cleanup(func() {
				_ = listener.Close()
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Error("peer observer did not join")
				}
			})
			env := &WasmEnv{DebugletID: uuid.New(), Policy: scheduler.Policy{Addresses: []string{"127.0.0.1"}}, Limiter: app.NewLimiter(zap.NewNop()), Registry: &socket.SocketRegistry{}, Logger: zap.NewNop().Sugar()}
			env.Net = testPolicy(t, netpolicy.Run{Addresses: env.Policy.Addresses})
			t.Cleanup(func() { _ = env.Close() })
			if phase != "missing_limit" {
				env.Limiter.SetExecutorCapacity(app.Gigabit)
				env.Limiter.SetAddrCapacity("127.0.0.1", app.Gigabit)
				if err := env.Limiter.InsertDebuglet(env.DebugletID, 0, app.Gigabit, env.Policy.Addresses); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "closed_registry" {
				pc, err := fallback.NewFallbackCount()
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				env.PacketCount = pc
				if err := env.Registry.CloseAll(); err != nil {
					t.Fatal(err)
				}
			}
			mod := newGuestModule(t)
			addr := listener.Addr().String()
			if !mod.Memory().Write(1024, []byte(addr)) {
				t.Fatal("write guest address")
			}
			trap := hostTrap(func() { _ = HostConnect(env, socket.SocketTypeTCP)(ctx, mod, 1024, uint32(len(addr))) })
			if trap == nil {
				t.Fatal("rejected connection did not trap")
			}
			if phase == "closed_registry" && !errors.Is(trap, net.ErrClosed) {
				t.Errorf("registry rejection=%v", trap)
			}
			select {
			case <-done:
				if peerErr != nil {
					t.Fatal(peerErr)
				}
			case <-ctx.Done():
				t.Fatal("peer closure not observed")
			}
		})
	}
}

func TestHostAcceptClosesLateConnection(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	id := uuid.New()
	limiter := app.NewLimiter(zap.NewNop())
	limiter.SetExecutorCapacity(app.Gigabit)
	limiter.SetAddrCapacity("127.0.0.1", app.Gigabit)
	if err := limiter.InsertDebuglet(id, 0, app.Gigabit, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	counter, err := fallback.NewFallbackCount()
	if err != nil {
		t.Fatal(err)
	}
	defer counter.Close()
	env := &WasmEnv{
		DebugletID:  id,
		Policy:      scheduler.Policy{Addresses: []string{"127.0.0.1"}, ListenTCP: true},
		Limiter:     limiter,
		PacketCount: counter,
		TcpServer:   listener,
		Registry:    &socket.SocketRegistry{},
		Logger:      zap.NewNop().Sugar(),
	}
	env.Net = testPolicy(t, netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true})
	if err := env.Registry.CloseAll(); err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	trap := hostTrap(func() { _ = HostAcceptTCP(env)(context.Background()) })
	if !errors.Is(trap, net.ErrClosed) {
		t.Fatalf("late accept=%v", trap)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("late accepted socket survived: %d,%v", n, err)
	}
}

type heldConstructorCounter struct {
	ratelimit.PacketCount
	entered, release         chan struct{}
	closes                   atomic.Int32
	constructorErr, closeErr error
}

func (c *heldConstructorCounter) Attach(conn net.Conn, _ uuid.UUID, _ string) (net.Conn, error) {
	return &heldConstructorConn{Conn: conn, owner: c}, nil
}
func (c *heldConstructorCounter) SetLimit(string, uuid.UUID, app.Bitrate) error {
	return c.constructorErr
}

type heldConstructorConn struct {
	net.Conn
	owner *heldConstructorCounter
}

func (c *heldConstructorConn) Close() error {
	c.owner.closes.Add(1)
	close(c.owner.entered)
	<-c.owner.release
	return errors.Join(c.Conn.Close(), c.owner.closeErr)
}

func TestHostConnectLateConstructorCloseErrorReachesFinalCleanup(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	counter := &heldConstructorCounter{entered: make(chan struct{}), release: make(chan struct{}), constructorErr: errors.New("limit rejected"), closeErr: errors.New("late wrapper close failure")}
	env := &WasmEnv{DebugletID: uuid.New(), Policy: scheduler.Policy{Addresses: []string{"127.0.0.1"}}, Limiter: app.NewLimiter(zap.NewNop()), PacketCount: counter, Registry: &socket.SocketRegistry{}, Logger: zap.NewNop().Sugar()}
	env.Net = testPolicy(t, netpolicy.Run{Addresses: env.Policy.Addresses})
	env.Limiter.SetExecutorCapacity(app.Gigabit)
	env.Limiter.SetAddrCapacity("127.0.0.1", app.Gigabit)
	if err := env.Limiter.InsertDebuglet(env.DebugletID, 0, app.Gigabit, env.Policy.Addresses); err != nil {
		t.Fatal(err)
	}
	mod := newGuestModule(t)
	addr := listener.Addr().String()
	if !mod.Memory().Write(1024, []byte(addr)) {
		t.Fatal("write guest address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var once sync.Once
	unblock := func() { once.Do(func() { close(counter.release) }) }
	done := make(chan struct{})
	var trap error
	go func() {
		defer close(done)
		trap = hostTrap(func() { _ = HostConnect(env, socket.SocketTypeTCP)(ctx, mod, 1024, uint32(len(addr))) })
	}()
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("constructor did not join")
		}
		_ = env.Close()
	})
	_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	select {
	case <-counter.entered:
	case <-done:
		t.Fatalf("constructor unexpectedly returned: %v", trap)
	case <-ctx.Done():
		t.Fatal("constructor did not reach Close")
	}
	if err := env.Close(); err != nil {
		t.Fatalf("initial watcher Close=%v", err)
	}
	unblock()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("constructor did not finish")
	}
	if !errors.Is(trap, counter.constructorErr) || !errors.Is(trap, counter.closeErr) {
		t.Fatalf("constructor result=%v", trap)
	}
	finalErr := env.Close()
	if !errors.Is(finalErr, counter.closeErr) || errors.Is(finalErr, counter.constructorErr) {
		t.Fatalf("cleanup classification=%v", finalErr)
	}
	if counter.closes.Load() != 1 {
		t.Fatalf("wrapper closes=%d", counter.closes.Load())
	}
}
