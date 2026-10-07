// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestHostEgressICMPPayload(t *testing.T) {
	listener, err := net.ListenPacket("ip4:icmp", "127.0.0.1")
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skip("raw ICMP capability unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, RequireICMP: true, Egress: netpolicy.NewEgress(hostEgressGrant())})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	handle, err := connectSocket(ctx, ctx, env, socket.SocketTypeICMP4, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := env.Registry.Get(handle)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := 1; sequence <= 2; sequence++ {
		message := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 29433, Seq: sequence, Data: make([]byte, 8)}}
		payload, err := message.Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Write(payload); err != nil || n != 16 {
			t.Fatalf("ICMP write=%d,%v", n, err)
		}
	}
	if n, err := conn.Write(make([]byte, 16)); n != 0 || !errors.Is(err, netpolicy.ErrDenied) {
		t.Fatalf("ICMP escaped budget=%d,%v", n, err)
	}
	seen := map[int]bool{}
	for len(seen) < 2 {
		buf := make([]byte, 256)
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		message, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if body, ok := message.Body.(*icmp.Echo); ok && message.Type == ipv4.ICMPTypeEcho && body.ID == 29433 {
			seen[body.Seq] = true
		}
	}
}
