// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

type ioScript struct {
	*scriptedSocket
	written  int
	writeErr error
}

func (s *ioScript) Write([]byte) (int, error) { return s.written, s.writeErr }

func TestHostIOPreservesCountAndOutcome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status uint32
	}{
		{"timeout", os.ErrDeadlineExceeded, guestio.Timeout},
		{"reset", syscall.ECONNRESET, guestio.Reset},
		{"closed", net.ErrClosed, guestio.Closed},
		{"EOF", io.EOF, guestio.EOF},
		{"refused", syscall.ECONNREFUSED, guestio.Refused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mod, env := newGuestModule(t), newReceiveEnv()
			s := &ioScript{scriptedSocket: &scriptedSocket{typ: socket.SocketTypeTCP,
				results: []readResult{{data: []byte("abc"), n: 3, err: tc.err}}}, written: 3, writeErr: tc.err}
			h, err := env.Registry.Add(s)
			if err != nil {
				t.Fatal(err)
			}
			fillGuest(t, mod, 16, 8, '.')
			read := HostIORead(env)(context.Background(), mod, h, 16, 8)
			if uint32(read) != 3 || uint32(read>>32) != tc.status {
				t.Fatalf("read result=%x", read)
			}
			assertGuest(t, mod, 16, 8, []byte("abc"), '.')
			write := HostIOWrite(env)(context.Background(), mod, h, 16, 8)
			if write != read {
				t.Fatalf("write=%x read=%x", write, read)
			}
		})
	}
}

func TestHostIOTrapsInvalidInputsAndReportsClosed(t *testing.T) {
	mod, env := newGuestModule(t), newReceiveEnv()
	h, err := env.Registry.Add(&scriptedSocket{typ: socket.SocketTypeTCP})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if result := HostIOClose(env)(ctx, h); result != 0 {
		t.Fatal(result)
	}
	if result := HostIORead(env)(ctx, mod, h, 0, 4); uint32(result>>32) != guestio.Closed {
		t.Fatal(result)
	}
	for _, fn := range []func(){
		func() { HostIORead(env)(ctx, mod, h, wasmPageSize, 4) },
		func() { HostIOWrite(env)(ctx, mod, h, wasmPageSize, 4) },
		func() { HostIORead(env)(ctx, mod, -1, 0, 4) },
		func() { HostIOClose(env)(ctx, 100) },
		func() { HostIODeadline(env)(ctx, h, 2, 0) },
		func() { HostIODial(env)(ctx, mod, 0, wasmPageSize, 4, 0) },
	} {
		if trap := hostTrap(fn); trap == nil {
			t.Error("invalid input did not trap")
		}
	}
}

func TestHostIORealPipeDeadlines(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	mod, env := newGuestModule(t), newReceiveEnv()
	h, err := env.Registry.Add(socket.NewGenericSocket(left, socket.SocketTypeTCP, "pipe"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, write := range []uint32{0, 1} {
		if result := HostIODeadline(env)(ctx, h, write, time.Now().Add(-time.Second).UnixNano()); result != 0 {
			t.Fatal(result)
		}
		operation := HostIORead(env)
		if write == 1 {
			operation = HostIOWrite(env)
		}
		if result := operation(ctx, mod, h, 0, 4); uint32(result>>32) != guestio.Timeout {
			t.Fatal(result)
		}
		if result := HostIODeadline(env)(ctx, h, write, 0); result != 0 {
			t.Fatal(result)
		}
	}
	if result := HostIOClose(env)(ctx, h); result != 0 {
		t.Fatal(result)
	}
	if result := HostIOWrite(env)(ctx, mod, h, 0, 4); uint32(result>>32) != guestio.Closed {
		t.Fatal(result)
	}
}

// A socket closed because its destination was denied is an ordinary closed
// socket to the guest, and a denied dial is a policy denial.
func TestHostIORevokedAndDeniedDestinations(t *testing.T) {
	mod, env := newGuestModule(t), newReceiveEnv()
	h, err := env.Registry.Add(&scriptedSocket{typ: socket.SocketTypeTCP})
	if err != nil {
		t.Fatal(err)
	}
	if closed := env.Registry.CloseRemote(func(string) bool { return true }); closed != 1 {
		t.Fatalf("closed %d sockets", closed)
	}
	ctx := context.Background()
	if result := HostIORead(env)(ctx, mod, h, 0, 4); uint32(result>>32) != guestio.Closed {
		t.Fatalf("read of a revoked socket = %x", result)
	}
	if result := HostIOClose(env)(ctx, h); uint32(result>>32) != guestio.Closed {
		t.Fatalf("close of a revoked socket = %x", result)
	}
	if result := ioResult(-1, fmt.Errorf("connect: %w", netpolicy.ErrDestinationDenied)); uint32(result>>32) != guestio.Denied {
		t.Fatalf("denied dial = %x", result)
	}
}
