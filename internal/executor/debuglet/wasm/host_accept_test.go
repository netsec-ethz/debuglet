// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

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
