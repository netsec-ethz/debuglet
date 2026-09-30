// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

func TestHostSocketQuotaPrecedesDialAndPreservesSibling(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	node := socket.NewDescriptorBudget(2)
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	env.Budget = socket.NewBudget(socket.Limits{LiveSockets: 1, Listeners: 1, SocketAttempts: 2}, node)
	env.Registry = socket.NewSocketRegistry(env.Budget)
	sibling := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	sibling.Budget = socket.NewBudget(socket.DefaultLimits(), node)
	sibling.Registry = socket.NewSocketRegistry(sibling.Budget)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connect := func(e *WasmEnv) int32 {
		t.Helper()
		handle, err := connectSocket(ctx, ctx, e, socket.SocketTypeTCP, listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		peer, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		return handle
	}
	first := connect(env)
	if _, err := connectSocket(ctx, ctx, env, socket.SocketTypeTCP, listener.Addr().String()); !errors.Is(err, socket.ErrQuota) {
		t.Fatalf("live quota=%v", err)
	}
	_ = listener.SetDeadline(time.Now().Add(20 * time.Millisecond))
	if peer, err := listener.AcceptTCP(); err == nil {
		peer.Close()
		t.Fatal("quota refusal dialed peer")
	}
	_ = listener.SetDeadline(time.Time{})
	other := connect(sibling)
	if err := sibling.Registry.Close(other); err != nil {
		t.Fatal(err)
	}
	if err := env.Registry.Close(first); err != nil {
		t.Fatal(err)
	}
	next := connect(env)
	if next == first {
		t.Fatal("reused stale guest handle")
	}
	if err := env.Registry.Close(next); err != nil {
		t.Fatal(err)
	}
	if _, err := connectSocket(ctx, ctx, env, socket.SocketTypeTCP, listener.Addr().String()); !errors.Is(err, socket.ErrQuota) {
		t.Fatalf("attempt quota=%v", err)
	}
	if result := ioResult(-1, socket.ErrQuota); uint32(result>>32) != guestio.Denied {
		t.Fatalf("quota status=%x", result)
	}
	_ = connect(sibling)
}

func TestHostAcceptReservesBeforeConsumingPendingPeer(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true})
	node := socket.NewDescriptorBudget(2)
	env.Budget = socket.NewBudget(socket.Limits{LiveSockets: 1, Listeners: 1, SocketAttempts: 3}, node)
	env.Registry = socket.NewSocketRegistry(env.Budget)
	listenReservation, err := env.Budget.ReserveListener()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.InstallTCP(listener, 0, listener.Addr().String(), listenReservation); err != nil {
		t.Fatal(err)
	}
	held, err := env.Registry.Reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	trap := hostTrap(func() { HostAcceptTCP(env)(context.Background()) })
	if !errors.Is(trap, socket.ErrQuota) {
		t.Fatalf("accept quota=%v", trap)
	}
	held.Release()
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	var handle int32
	if trap := hostTrap(func() { handle = HostAcceptTCP(env)(context.Background()) }); trap != nil {
		t.Fatalf("pending peer was lost: %v", trap)
	}
	read := make(chan error, 1)
	sock, err := env.Registry.Get(handle)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, err := sock.Read(make([]byte, 1)); read <- err }()
	if err := env.Close(); err != nil {
		t.Fatal(err)
	}
	if err := env.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("blocked read did not close")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read did not join")
	}
	// Both listener and accepted peer returned their shared capacity exactly once.
	replacement, err := socket.NewBudget(socket.DefaultLimits(), node).ReserveSocket(2)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Release()
}

func TestFailedDialReturnsLiveAndNodeReservation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	node := socket.NewDescriptorBudget(1)
	env.Budget = socket.NewBudget(socket.Limits{LiveSockets: 1, Listeners: 1, SocketAttempts: 2}, node)
	env.Registry = socket.NewSocketRegistry(env.Budget)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := connectSocket(ctx, ctx, env, socket.SocketTypeTCP, addr); err == nil || errors.Is(err, socket.ErrQuota) {
		t.Fatalf("failed dial=%v", err)
	}
	retry, err := env.Registry.Reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	retry.Release()
	if _, err := env.Registry.Reserve(1); !errors.Is(err, socket.ErrQuota) {
		t.Fatalf("failed attempt was not counted: %v", err)
	}
}
