// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

type cancelingAcceptResolver struct {
	cancel func()
	fail   bool
	calls  int
}

func (r *cancelingAcceptResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	r.calls++
	r.cancel()
	if r.fail {
		return nil, context.Cause(ctx)
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestAcceptTCPSocketCompletedAdmissionSurvivesPollExpiry(t *testing.T) {
	for _, mode := range []string{"poll expired", "run canceled", "admission timed out"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			acceptCtx, expire := context.WithCancelCause(ctx)
			defer expire(context.Canceled)
			resolver := &cancelingAcceptResolver{cancel: func() { expire(context.DeadlineExceeded) }}
			if mode == "run canceled" {
				resolver.cancel = cancel
			}
			resolver.fail = mode == "admission timed out"
			env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"peer.example"}, ListenTCP: true}, netpolicy.WithResolver(resolver))
			env.TcpServer = listener
			env.Registry = socket.NewSocketRegistry(socket.NewBudget(socket.Limits{LiveSockets: 1, Listeners: 1, SocketAttempts: 8}, socket.NewDescriptorBudget(1)))
			peer, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write([]byte("next phase")); err != nil {
				t.Fatal(err)
			}
			// Resolution completes after the kernel accept, exactly when the
			// polling context expires. No wall-clock scheduling race is needed.
			handle, err := acceptTCPSocket(ctx, acceptCtx, env)
			if resolver.calls != 1 || acceptCtx.Err() == nil {
				t.Fatalf("admission did not exercise expiry: calls=%d error=%v", resolver.calls, acceptCtx.Err())
			}
			if mode == "poll expired" {
				if err != nil || handle < 0 || ctx.Err() != nil {
					t.Fatalf("completed admission was discarded: handle=%d error=%v run=%v", handle, err, ctx.Err())
				}
				sock, err := env.Registry.Get(handle)
				if err != nil {
					t.Fatal(err)
				}
				payload := make([]byte, len("next phase"))
				if _, err := io.ReadFull(sock, payload); err != nil || string(payload) != "next phase" {
					t.Fatalf("accepted payload=%q error=%v", payload, err)
				}
				if err := env.Registry.Close(handle); err != nil {
					t.Fatal(err)
				}
			} else {
				want := context.Cause(acceptCtx)
				if handle != -1 || !errors.Is(err, want) || len(env.Registry.All()) != 0 {
					t.Fatalf("failed admission escaped: handle=%d error=%v want=%v", handle, err, want)
				}
				_, err = peer.Read(make([]byte, 1))
				var timeout net.Error
				if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
					t.Fatalf("refused connection was not closed: %v", err)
				}
			}
			reservation, err := env.Registry.Reserve(1)
			if err != nil {
				t.Fatal("accepted descriptor was not released:", err)
			}
			reservation.Release()
		})
	}
}

func TestHostIOAcceptOutcomes(t *testing.T) {
	for _, mode := range []string{"timeout", "run deadline", "canceled", "closed", "denied", "quota", "rejected peer"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			run := netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenTCP: mode != "denied"}
			env := policyEnv(t, localSpec(), run)
			env.TcpServer = listener
			// A timeout must release its live descriptor reservation.
			env.Registry = socket.NewSocketRegistry(socket.NewBudget(socket.Limits{LiveSockets: 1, Listeners: 1, SocketAttempts: 8}, socket.NewDescriptorBudget(1)))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout, want := int64(30*time.Millisecond), uint32(guestio.Timeout)
			switch mode {
			case "run deadline":
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 30*time.Millisecond)
				defer stop()
				timeout = int64(time.Hour)
			case "canceled":
				timer := time.AfterFunc(30*time.Millisecond, cancel)
				defer timer.Stop()
				timeout, want = 0, guestio.Canceled
			case "closed":
				_ = listener.Close()
				want = guestio.Closed
			case "denied":
				want = guestio.Denied
			case "quota":
				reserved, err := env.Registry.Reserve(1)
				if err != nil {
					t.Fatal(err)
				}
				defer reserved.Release()
				want = guestio.Denied
			case "rejected peer":
				dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}
				peer, err := dialer.Dial("tcp4", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
			}
			result := HostIOAcceptTCP(env)(ctx, timeout)
			if got := uint32(result >> 32); got != want {
				t.Fatalf("accept outcome %d, want %d", got, want)
			}
			if mode == "timeout" || mode == "rejected peer" {
				if result := HostIOAcceptTCP(env)(ctx, timeout); uint32(result>>32) != guestio.Timeout {
					t.Fatalf("live descriptor reservation leaked: %x", result)
				}
			}
		})
	}
}
