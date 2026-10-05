// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"errors"
	"net"
	"testing"
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
