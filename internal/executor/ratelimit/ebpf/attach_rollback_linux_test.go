// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/google/uuid"
)

type failingSendingConn struct {
	*net.UDPConn
	onSending func()
}

func (c *failingSendingConn) SendingSyscallConn() (syscall.RawConn, error) {
	c.onSending()
	return nil, errors.New("sending socket closed")
}

func TestBPFCounterAttachRollbackKeepsReusedDescriptor(t *testing.T) {
	counter := loopbackCounter(t)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	a, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	fd := socketFD(t, a)
	idB := uuid.New()
	var b net.Conn
	wrapped := &failingSendingConn{UDPConn: a, onSending: func() {
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		for range 8 {
			candidate, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = candidate.Close() })
			if socketFD(t, candidate) != fd {
				continue
			}
			b, err = counter.Attach(candidate, idB, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		t.Fatal("no new socket reused the descriptor")
	}}
	if _, err := counter.Attach(wrapped, uuid.New(), "127.0.0.1"); err == nil {
		t.Fatal("sending socket failure accepted")
	}
	defer b.Close()
	var association countDebugletUuid
	if err := counter.objs.DebugletSkMap.Lookup(uint32(fd), &association); err != nil {
		t.Fatalf("rollback deleted another run's socket association: %v", err)
	}
	if association.Uuid != [16]byte(idB) {
		t.Fatalf("socket belongs to %x, want %x", association.Uuid, idB)
	}
}
