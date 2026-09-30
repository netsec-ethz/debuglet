// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"go.uber.org/zap"
)

func TestBudgetSharesNodeCapacityAndReleasesOnce(t *testing.T) {
	node := NewDescriptorBudget(3)
	limits := Limits{LiveSockets: 1, Listeners: 1, SocketAttempts: 2}
	first, sibling := NewBudget(limits, node), NewBudget(limits, node)
	connection, err := first.ReserveSocket(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.ReserveSocket(1); !errors.Is(err, ErrQuota) {
		t.Fatalf("live limit: %v", err)
	}
	listener, err := sibling.ReserveListener()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sibling.ReserveListener(); !errors.Is(err, ErrQuota) {
		t.Fatalf("listener limit: %v", err)
	}
	if _, err := sibling.ReserveSocket(1); !errors.Is(err, ErrQuota) {
		t.Fatalf("node limit: %v", err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); connection.Release() }()
	}
	wg.Wait()
	next, err := first.ReserveSocket(2)
	if err != nil {
		t.Fatal(err)
	}
	next.Release()
	if _, err := first.ReserveSocket(1); !errors.Is(err, ErrQuota) {
		t.Fatalf("attempt limit: %v", err)
	}
	// Exhausting one run does not consume its sibling's remaining capacity.
	other, err := sibling.ReserveSocket(2)
	if err != nil {
		t.Fatal(err)
	}
	other.Release()
	listener.Release()
	if node.used != 0 {
		t.Fatalf("retained %d descriptors", node.used)
	}
}

func TestRegistryLoopbackChurnKeepsHandlesFiniteAndStale(t *testing.T) {
	node := NewDescriptorBudget(1)
	reg := NewSocketRegistry(NewBudget(Limits{1, 1, 3}, node))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for i := int32(0); i < 3; i++ {
		reservation, err := reg.Reserve(1)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			reservation.Release()
			t.Fatal(err)
		}
		peer, err := listener.Accept()
		if err != nil {
			conn.Close()
			reservation.Release()
			t.Fatal(err)
		}
		handle, err := reg.AddReserved(NewGenericSocket(conn, SocketTypeTCP, listener.Addr().String()), reservation)
		if err != nil || handle != i {
			t.Fatalf("handle=%d error=%v", handle, err)
		}
		reservation.Release() // Publication transferred capacity to the entry.
		if _, err := reg.Reserve(1); !errors.Is(err, ErrQuota) {
			t.Fatalf("live capacity was released before close: %v", err)
		}
		blocked := make(chan error, 1)
		go func() { _, err := conn.Read(make([]byte, 1)); blocked <- err }()
		if err := reg.Close(handle); err != nil {
			t.Fatal(err)
		}
		if err := lifecycleWait(t, blocked); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read did not unblock on close: %v", err)
		}
		peer.Close()
		if _, err := reg.Get(0); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("stale handle revived: %v", err)
		}
	}
	if _, err := reg.Reserve(1); !errors.Is(err, ErrQuota) {
		t.Fatalf("unbounded attempts: %v", err)
	}
	if len(reg.sockets) != 3 || node.used != 0 {
		t.Fatalf("handles=%d descriptors=%d", len(reg.sockets), node.used)
	}
	if err := reg.CloseAll(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryCloseRetainsReservationUntilJoined(t *testing.T) {
	node := NewDescriptorBudget(1)
	budget := NewBudget(Limits{1, 1, 2}, node)
	reg := NewSocketRegistry(budget)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	s := &lifecycleSocket{closeFn: func() error { close(entered); <-release; return nil }}
	handle, err := reg.Add(s)
	if err != nil {
		t.Fatal(err)
	}
	done := closeAsync(func() error { return reg.Close(handle) })
	lifecycleWait(t, entered)
	if _, err := budget.ReserveSocket(1); !errors.Is(err, ErrQuota) {
		t.Fatalf("released during close: %v", err)
	}
	unblock()
	if err := done.wait(t); err != nil {
		t.Fatal(err)
	}
	if err := reg.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if node.used != 0 || s.count.Load() != 1 {
		t.Fatalf("reservation=%d close count=%d", node.used, s.count.Load())
	}
}

func TestReservationFailureAndLatePublicationReleaseCapacity(t *testing.T) {
	node := NewDescriptorBudget(1)
	budget := NewBudget(Limits{1, 1, 3}, node)
	reg := NewSocketRegistry(budget)
	failed, err := reg.Reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	failed.Release()
	failed.Release()
	pending, err := reg.Reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.CloseAll(); err != nil {
		t.Fatal(err)
	}
	late := &lifecycleSocket{}
	if _, err := reg.AddReserved(late, pending); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late publication: %v", err)
	}
	if late.count.Load() != 1 || node.used != 0 {
		t.Fatalf("close=%d retained=%d", late.count.Load(), node.used)
	}
}

func TestSCIONCapacityCountsPendingDialsAndAllowsExistingKey(t *testing.T) {
	reg := NewSCIONConnRegistry(1)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	reg.dial = func(context.Context, string, *zap.SugaredLogger, tagger.TaggerInterface) (*SCIONConn, error) {
		calls.Add(1)
		close(entered)
		<-release
		return &SCIONConn{}, nil
	}
	done := make(chan error, 1)
	go func() { _, err := reg.GetOrDial(context.Background(), "first", zap.NewNop().Sugar(), nil); done <- err }()
	lifecycleWait(t, entered)
	if _, err := reg.GetOrDial(context.Background(), "second", zap.NewNop().Sugar(), nil); !errors.Is(err, ErrQuota) {
		close(release)
		t.Fatalf("pending capacity: %v", err)
	}
	close(release)
	if err := lifecycleWait(t, done); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.GetOrDial(context.Background(), "first", zap.NewNop().Sugar(), nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("dial count=%d", calls.Load())
	}
	if err := reg.CloseAll(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryRequiresExplicitBudget(t *testing.T) {
	reg := NewSocketRegistry(nil)
	if _, err := reg.Reserve(1); err == nil {
		t.Fatal("missing budget allowed a reservation")
	}
	s := &lifecycleSocket{}
	if _, err := reg.Add(s); err == nil {
		t.Fatal("missing budget admitted socket")
	}
	if s.count.Load() != 1 {
		t.Fatal("rejected socket was not consumed")
	}
}
