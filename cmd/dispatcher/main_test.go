package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"go.uber.org/zap"
)

func TestDemoListenerOwnership(t *testing.T) {
	t.Run("combined listener cancels an idle protocol handshake", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer lis.Close()
		accepted := make(chan struct{})
		bidi, err := rpc.NewBidiServer(zap.NewNop(), nil, "00000000-0000-4000-8000-000000000001", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		defer bidi.Close()
		done := make(chan error, 1)
		go func() {
			done <- serveCombined(ctx, &observedListener{Listener: lis, accepted: accepted}, &dispatcher.Dispatcher{Bidi: bidi}, &config.DispatcherConfig{TLS: config.TLSConfig{Disable: true}}, nil, nil, zap.NewNop())
		}()
		conn, err := net.DialTimeout("tcp", lis.Addr().String(), time.Second)
		if err != nil {
			cancel()
			<-done
			t.Fatal(err)
		}
		defer conn.Close()
		defer func() {
			cancel()
			conn.Close()
			if done != nil {
				<-done
			}
		}()
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatal("connection not accepted")
		}
		cancel()
		select {
		case err := <-done:
			done = nil
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("combined listener did not join")
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Fatalf("idle connection remains open: %v", err)
		}
	})
	t.Run("actual ephemeral loopback addresses", func(t *testing.T) {
		httpL, grpcL, err := bindDispatcherListeners(context.Background(), config.ServerConfig{BindHost: "127.0.0.1"}, (&net.ListenConfig{}).Listen)
		if err != nil {
			t.Fatal(err)
		}
		defer httpL.Close()
		defer grpcL.Close()
		for _, lis := range []net.Listener{httpL, grpcL} {
			addr := lis.Addr().(*net.TCPAddr)
			if !addr.IP.Equal(net.ParseIP("127.0.0.1")) || addr.Port == 0 {
				t.Fatalf("not actual loopback binding: %v", addr)
			}
		}
		if httpL.Addr().String() == grpcL.Addr().String() {
			t.Fatal("listeners share an address")
		}
	})
	t.Run("second bind failure closes first listener", func(t *testing.T) {
		reserved, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer reserved.Close()
		var first net.Listener
		listen := func(ctx context.Context, network, addr string) (net.Listener, error) {
			lis, err := (&net.ListenConfig{}).Listen(ctx, network, addr)
			if first == nil && err == nil {
				first = lis
			}
			return lis, err
		}
		h, g, err := bindDispatcherListeners(context.Background(), config.ServerConfig{BindHost: "127.0.0.1", GRPCPort: reserved.Addr().(*net.TCPAddr).Port}, listen)
		if first != nil {
			defer first.Close()
		}
		if err == nil || h != nil || g != nil || first == nil {
			t.Fatalf("bind result: %v %v %v first=%v", h, g, err, first)
		}
		_, err = first.Accept()
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("first listener not closed: %v", err)
		}
	})
	t.Run("first bind failure", func(t *testing.T) {
		sentinel := errors.New("listen failed")
		calls := 0
		h, g, err := bindDispatcherListeners(context.Background(), config.ServerConfig{}, func(context.Context, string, string) (net.Listener, error) { calls++; return nil, sentinel })
		if !errors.Is(err, sentinel) || h != nil || g != nil || calls != 1 {
			t.Fatalf("bind result %v %v %v calls=%d", h, g, err, calls)
		}
	})
}

type observedListener struct {
	net.Listener
	accepted chan struct{}
}

func (l *observedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		close(l.accepted)
	}
	return conn, err
}
