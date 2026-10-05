// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type remoteSocket struct {
	fakeSocket
	remote string
}

func (s *remoteSocket) RemoteAddr() string { return s.remote }

func TestCloseRemoteClosesOnlyMatchingSockets(t *testing.T) {
	reg := NewSocketRegistry(NewBudget(DefaultLimits(), NewDescriptorBudget(DefaultNodeDescriptors)))
	denied := &remoteSocket{fakeSocket: fakeSocket{socketType: SocketTypeTCP}, remote: "93.184.216.7:443"}
	datagram := &remoteSocket{fakeSocket: fakeSocket{socketType: SocketTypeUDP}, remote: "93.184.216.7:53"}
	kept := &remoteSocket{fakeSocket: fakeSocket{socketType: SocketTypeTCP}, remote: "93.184.216.8:443"}
	var handles []int32
	for _, s := range []Socket{denied, datagram, kept} {
		h, err := reg.Add(s)
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, h)
	}
	match := func(remote string) bool {
		host, _, _ := net.SplitHostPort(remote)
		return host == "93.184.216.7"
	}
	if closed := reg.CloseRemote(match); closed != 2 {
		t.Fatalf("closed %d sockets, want 2", closed)
	}
	if !denied.closed || !datagram.closed || kept.closed {
		t.Fatalf("closed tcp=%v udp=%v kept=%v", denied.closed, datagram.closed, kept.closed)
	}
	for _, h := range handles[:2] {
		if _, err := reg.Get(h); !errors.Is(err, ErrRevoked) || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("revoked handle %d: %v", h, err)
		}
	}
	if s, err := reg.Get(handles[2]); err != nil || s != kept {
		t.Fatalf("kept handle: %v, %v", s, err)
	}
	// A repeated revocation closes nothing twice, and the run still opens sockets.
	if closed := reg.CloseRemote(match); closed != 0 {
		t.Fatalf("closed %d sockets again", closed)
	}
	if _, err := reg.Add(&remoteSocket{fakeSocket: fakeSocket{socketType: SocketTypeTCP}, remote: "93.184.216.9:443"}); err != nil {
		t.Fatal("registry refused a socket after a revocation:", err)
	}
	if err := reg.CloseAll(); err != nil {
		t.Fatal(err)
	}
}

// TestCloseRemoteJoinsACloseInProgress states that a revocation does not
// return while a matching socket's close, started by another closer, is
// still running: the acknowledgement it backs must follow that close.
func TestCloseRemoteJoinsACloseInProgress(t *testing.T) {
	for _, closer := range []string{"Close", "CloseAll"} {
		t.Run(closer, func(t *testing.T) {
			reg := NewSocketRegistry(NewBudget(DefaultLimits(), NewDescriptorBudget(DefaultNodeDescriptors)))
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			held := &lifecycleSocket{closeFn: func() error { close(entered); <-release; return nil }}
			handle, err := reg.Add(held)
			if err != nil {
				t.Fatal(err)
			}
			var first *closeResult
			if closer == "Close" {
				first = closeAsync(func() error { return reg.Close(handle) })
			} else {
				first = closeAsync(reg.CloseAll)
			}
			t.Cleanup(func() { unblock(); first.wait(t) })
			// The socket is detached and its underlying close is held.
			lifecycleWait(t, entered)
			var revoked atomic.Int32
			remote := closeAsync(func() error {
				revoked.Store(int32(reg.CloseRemote(func(addr string) bool { return addr == held.RemoteAddr() })))
				return nil
			})
			t.Cleanup(func() { unblock(); remote.wait(t) })
			select {
			case <-remote.done:
				t.Fatal("CloseRemote returned while the matching socket's close was held")
			case <-time.After(100 * time.Millisecond):
			}
			unblock()
			remote.wait(t)
			if n := revoked.Load(); n != 0 {
				t.Fatalf("CloseRemote counted %d sockets another closer detached", n)
			}
			if held.count.Load() != 1 {
				t.Fatal("underlying socket closed more than once")
			}
		})
	}
}
