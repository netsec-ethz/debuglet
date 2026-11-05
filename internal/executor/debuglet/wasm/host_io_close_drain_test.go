// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

type closeDrainSocket struct {
	*scriptedSocket
	drain    func(context.Context) error
	closeErr error
	events   []string
}

func (s *closeDrainSocket) DrainTCP(ctx context.Context) error {
	s.events = append(s.events, "drain")
	return s.drain(ctx)
}

func (s *closeDrainSocket) Close() error {
	s.events = append(s.events, "close")
	return s.closeErr
}

func TestHostIOCloseDrainsBeforeReleasingSocket(t *testing.T) {
	closeFailed := errors.New("close failed")
	for _, tc := range []struct {
		name     string
		drainErr error
		closeErr error
		cancel   bool
		want     uint32
	}{
		{name: "delivered", want: guestio.OK},
		{name: "drain timeout", drainErr: context.DeadlineExceeded, want: guestio.Timeout},
		{name: "run canceled", cancel: true, want: guestio.Canceled},
		{name: "close failure", closeErr: closeFailed, want: guestio.Failure},
		{name: "timeout and close failure", drainErr: context.DeadlineExceeded, closeErr: closeFailed, want: guestio.Timeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newReceiveEnv()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			s := &closeDrainSocket{
				scriptedSocket: &scriptedSocket{typ: socket.SocketTypeTCP},
				closeErr:       tc.closeErr,
				drain: func(received context.Context) error {
					if tc.cancel {
						if received.Err() == nil {
							t.Error("drain lost the canceled run context")
						}
						return received.Err()
					}
					return tc.drainErr
				},
			}
			handle, err := env.Registry.Add(s)
			if err != nil {
				t.Fatal(err)
			}
			result := HostIOClose(env)(ctx, handle)
			if status := uint32(result >> 32); status != tc.want {
				t.Fatalf("close status %d, want %d", status, tc.want)
			}
			if !slices.Equal(s.events, []string{"drain", "close"}) {
				t.Fatalf("socket events %v, want drain then close", s.events)
			}
			if _, err := env.Registry.Get(handle); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("socket remained available after close: %v", err)
			}
		})
	}
}

func TestRevocationClosesWithoutDraining(t *testing.T) {
	env := newReceiveEnv()
	s := &closeDrainSocket{
		scriptedSocket: &scriptedSocket{typ: socket.SocketTypeTCP},
		drain: func(context.Context) error {
			t.Fatal("revocation must not wait for queued traffic to drain")
			return nil
		},
	}
	handle, err := env.Registry.Add(s)
	if err != nil {
		t.Fatal(err)
	}
	if closed := env.Registry.CloseRemote(func(string) bool { return true }); closed != 1 {
		t.Fatalf("revoked sockets %d, want 1", closed)
	}
	if !slices.Equal(s.events, []string{"close"}) {
		t.Fatalf("revocation events %v, want immediate close", s.events)
	}
	if _, err := env.Registry.Get(handle); !errors.Is(err, socket.ErrRevoked) {
		t.Fatalf("revoked handle error %v", err)
	}
}
