// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package socket

import (
	"errors"
	"io"
	"net"
	"testing"
)

// fakeSocket is a test double that implements the Socket interface.
type fakeSocket struct {
	socketType SocketType
	closed     bool
	writeData  []byte
}

func (f *fakeSocket) Type() SocketType { return f.socketType }
func (f *fakeSocket) Read(b []byte) (int, error) {
	if f.closed {
		return 0, io.ErrClosedPipe
	}
	return 0, io.EOF
}
func (f *fakeSocket) Write(b []byte) (int, error) {
	if f.closed {
		return 0, io.ErrClosedPipe
	}
	f.writeData = append(f.writeData, b...)
	return len(b), nil
}
func (f *fakeSocket) Close() error {
	f.closed = true
	return nil
}
func (f *fakeSocket) Addr() string       { return "fake.com" }
func (f *fakeSocket) RemoteAddr() string { return "fake.com:1234" }

// TestSocketRegistryAddAndGet verifies that sockets can be added and retrieved
// by their returned handle.
func TestSocketRegistryAddAndGet(t *testing.T) {
	reg := &SocketRegistry{}

	tcp := &fakeSocket{socketType: SocketTypeTCP}
	tls := &fakeSocket{socketType: SocketTypeTLS}

	h1, addErr := reg.Add(tcp)
	if addErr != nil {
		t.Fatal(addErr)
	}
	h2, addErr := reg.Add(tls)
	if addErr != nil {
		t.Fatal(addErr)
	}

	if h1 != 0 {
		t.Errorf("expected first handle to be 0, got %d", h1)
	}
	if h2 != 1 {
		t.Errorf("expected second handle to be 1, got %d", h2)
	}

	got1, err := reg.Get(h1)
	if err != nil {
		t.Fatalf("Get(%d) error: %v", h1, err)
	}
	if got1.Type() != SocketTypeTCP {
		t.Errorf("expected SocketTypeTCP, got %v", got1.Type())
	}

	got2, err := reg.Get(h2)
	if err != nil {
		t.Fatalf("Get(%d) error: %v", h2, err)
	}
	if got2.Type() != SocketTypeTLS {
		t.Errorf("expected SocketTypeTLS, got %v", got2.Type())
	}
}

// TestSocketRegistryInvalidHandle verifies that Get and Close return an error
// for out-of-range handles.
func TestSocketRegistryInvalidHandle(t *testing.T) {
	reg := &SocketRegistry{}

	if _, err := reg.Get(0); err == nil {
		t.Error("expected error for empty registry, got nil")
	}
	if _, err := reg.Get(-1); err == nil {
		t.Error("expected error for negative handle, got nil")
	}
	if err := reg.Close(5); err == nil {
		t.Error("expected error for out-of-range close, got nil")
	}
}

// TestSocketRegistryClose verifies that closing a handle marks the socket as
// closed and prevents subsequent access.
func TestSocketRegistryClose(t *testing.T) {
	reg := &SocketRegistry{}
	sock := &fakeSocket{socketType: SocketTypeTCP}
	h, addErr := reg.Add(sock)
	if addErr != nil {
		t.Fatal(addErr)
	}

	if err := reg.Close(h); err != nil {
		t.Fatalf("Close(%d) unexpected error: %v", h, err)
	}
	if !sock.closed {
		t.Error("expected underlying socket to be closed")
	}

	// Subsequent Get should fail.
	if _, err := reg.Get(h); err == nil {
		t.Error("expected error after close, got nil")
	}

	// Closing again should be a no-op (not an error).
	if err := reg.Close(h); err != nil {
		t.Errorf("double-close should be a no-op, got error: %v", err)
	}
}

// TestSocketRegistryCloseAll verifies that CloseAll closes every open socket.
func TestSocketRegistryCloseAll(t *testing.T) {
	reg := &SocketRegistry{}

	sockets := []*fakeSocket{
		{socketType: SocketTypeTCP},
		{socketType: SocketTypeTLS},
		{socketType: SocketTypeTCP},
	}
	for _, s := range sockets {
		reg.Add(s)
	}

	reg.CloseAll()

	for i, s := range sockets {
		if !s.closed {
			t.Errorf("socket %d was not closed by CloseAll", i)
		}
	}
}

// TestSocketRegistryCloseAllIdempotent verifies that CloseAll on an empty or
// already-closed registry is safe.
func TestSocketRegistryCloseAllIdempotent(t *testing.T) {
	reg := &SocketRegistry{}
	reg.CloseAll() // must not panic

	sock := &fakeSocket{socketType: SocketTypeTCP}
	if _, err := reg.Add(sock); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late Add: %v", err)
	}
	if !sock.closed {
		t.Fatal("late socket was not closed")
	}
	reg.CloseAll()
	reg.CloseAll() // second call must not panic or error
}
