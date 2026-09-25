package hostconn

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
)

type countedConn struct {
	net.Conn
	count atomic.Int32
	err   error
}

func (c *countedConn) Close() error { c.count.Add(1); return errors.Join(c.Conn.Close(), c.err) }

type constructorCounter struct {
	ratelimit.PacketCount
	attach   func(net.Conn) (net.Conn, error)
	limitErr error
}

func (c *constructorCounter) Attach(conn net.Conn, _ uuid.UUID, _ string) (net.Conn, error) {
	return c.attach(conn)
}
func (c *constructorCounter) SetLimit(string, uuid.UUID, app.Bitrate) error { return c.limitErr }

func TestConstructorConsumesConnectionOnEveryFailure(t *testing.T) {
	sentinel := errors.New("constructor failure")
	for _, phase := range []string{"no_counter", "attach", "attached_error", "nil_attached", "limit"} {
		t.Run(phase, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			raw := &countedConn{Conn: a}
			defer raw.Conn.Close()
			wrapper := &countedConn{Conn: raw}
			counter := &constructorCounter{attach: func(net.Conn) (net.Conn, error) { return wrapper, nil }}
			var pc ratelimit.PacketCount = counter
			switch phase {
			case "no_counter":
				pc = nil
			case "attach":
				counter.attach = func(net.Conn) (net.Conn, error) { return nil, sentinel }
			case "attached_error":
				counter.attach = func(net.Conn) (net.Conn, error) { return wrapper, sentinel }
			case "nil_attached":
				counter.attach = func(net.Conn) (net.Conn, error) { return nil, nil }
			case "limit":
				counter.limitErr = sentinel
			}
			got, err := NewConnection(context.Background(), pc, uuid.New(), raw, HostConnOpts{})
			if err == nil || got != nil {
				t.Fatalf("constructor=%v,%v", got, err)
			}
			if raw.count.Load() != 1 {
				t.Fatalf("original closes=%d", raw.count.Load())
			}
			want := int32(0)
			if phase == "limit" || phase == "attached_error" {
				want = 1
			}
			if wrapper.count.Load() != want {
				t.Fatalf("wrapper closes=%d want%d", wrapper.count.Load(), want)
			}
		})
	}
}

func TestHostConnConcurrentCloseReadAndAddress(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	sentinel := errors.New("underlying close error")
	raw := &countedConn{Conn: a, err: sentinel}
	defer a.Close()
	counter := &constructorCounter{attach: func(c net.Conn) (net.Conn, error) { return c, nil }}
	hc, err := NewConnection(context.Background(), counter, uuid.New(), raw, HostConnOpts{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = hc.Addr()
			_ = hc.RemoteAddr()
			_, _ = hc.Read(make([]byte, 1))
			_, _ = hc.Write([]byte{1})
			if !errors.Is(hc.Close(), sentinel) {
				t.Error("close error lost")
			}
		}()
	}
	close(start)
	if !errors.Is(hc.Close(), sentinel) {
		t.Error("initial error lost")
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("owned calls did not join")
	}
	if raw.count.Load() != 1 {
		t.Fatalf("closes=%d", raw.count.Load())
	}
	_ = hc.Addr()
	_ = hc.RemoteAddr()
}
