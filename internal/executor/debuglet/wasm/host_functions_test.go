// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
)

// memoryOnlyModule is a hand-assembled WebAssembly binary containing nothing
// but one linear memory of one 64 KiB page, exported as "memory". It has no
// type, function, import, start or code section, so instantiating it runs no
// guest code; it only provides a real api.Module whose Memory() backs the
// buffers handed to the host functions under test.
//
//	00 61 73 6d              magic "\0asm"
//	01 00 00 00              binary format version 1
//	05 03                    memory section (id 5), 3 payload bytes
//	   01                    one memory
//	   00 01                 limits: flags 0 (no maximum), min 1 page
//	07 0a                    export section (id 7), 10 payload bytes
//	   01                    one export
//	   06 "memory"           name length 6, UTF-8 name
//	   02 00                 export kind 2 (memory), index 0
var memoryOnlyModule = []byte{
	0x00, 0x61, 0x73, 0x6d,
	0x01, 0x00, 0x00, 0x00,
	0x05, 0x03, 0x01, 0x00, 0x01,
	0x07, 0x0a, 0x01, 0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
}

// wasmPageSize is the size of the single page the fixture exports.
const wasmPageSize = 65536

// newGuestModule instantiates memoryOnlyModule with wazero and returns the
// resulting module. The runtime is closed when the test finishes.
func newGuestModule(t *testing.T) api.Module {
	t.Helper()
	ctx := context.Background()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	t.Cleanup(func() { _ = rt.Close(ctx) })

	mod, err := rt.Instantiate(ctx, memoryOnlyModule)
	if err != nil {
		t.Fatalf("instantiate memory-only module: %v", err)
	}
	if mod.Memory() == nil {
		t.Fatal("fixture module exports no memory")
	}
	if got := mod.Memory().Size(); got != wasmPageSize {
		t.Fatalf("fixture memory size = %d, want %d", got, wasmPageSize)
	}
	return mod
}

// readResult is one scripted result of scriptedSocket.Read: data is copied
// into the caller's buffer and (n, err) is returned unchanged, so the fake can
// produce every combination in the shared contract table, including data
// together with an error and (0, nil).
type readResult struct {
	data []byte
	n    int
	err  error
}

// scriptedSocket is an in-package socket.Socket whose Read returns scripted
// results in order and records every call together with the length of the
// buffer it was given.
type scriptedSocket struct {
	typ     socket.SocketType
	results []readResult
	calls   int
	bufLens []int
}

func (s *scriptedSocket) Read(b []byte) (int, error) {
	s.calls++
	s.bufLens = append(s.bufLens, len(b))
	if s.calls > len(s.results) {
		return 0, fmt.Errorf("scriptedSocket: unexpected Read call %d", s.calls)
	}
	r := s.results[s.calls-1]
	if len(r.data) > len(b) {
		return 0, fmt.Errorf("scriptedSocket: scripted %d bytes do not fit into %d-byte buffer", len(r.data), len(b))
	}
	copy(b, r.data)
	return r.n, r.err
}

func (s *scriptedSocket) Write(b []byte) (int, error) { return len(b), nil }
func (s *scriptedSocket) Close() error                { return nil }
func (s *scriptedSocket) Type() socket.SocketType     { return s.typ }
func (s *scriptedSocket) Addr() string                { return "127.0.0.1" }
func (s *scriptedSocket) RemoteAddr() string          { return "127.0.0.1:0" }

// newReceiveEnv returns a WasmEnv with an empty registry and a no-op logger,
// which is all HostReceiveData touches.
func newReceiveEnv() *WasmEnv {
	return &WasmEnv{
		Registry: &socket.SocketRegistry{},
		Logger:   zap.NewNop().Sugar(),
	}
}

// callReceive invokes the host function and converts a host panic, which the
// engine turns into a guest trap, into a returned error.
func callReceive(fn func(context.Context, api.Module, int32, uint32, uint32) int32, mod api.Module, handle int32, ptr, length uint32) (n int32, trap error) {
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				trap = err
				return
			}
			trap = fmt.Errorf("non-error panic value: %v", r)
		}
	}()
	n = fn(context.Background(), mod, handle, ptr, length)
	return n, nil
}

// fillGuest writes len(n) copies of marker at ptr so tests can distinguish
// bytes written by the read from bytes left untouched.
func fillGuest(t *testing.T, mod api.Module, ptr, n uint32, marker byte) {
	t.Helper()
	if !mod.Memory().Write(ptr, bytes.Repeat([]byte{marker}, int(n))) {
		t.Fatalf("prefill guest memory at %d len %d", ptr, n)
	}
}

// assertGuest checks that guest memory at ptr holds payload followed by
// tail untouched marker bytes up to length.
func assertGuest(t *testing.T, mod api.Module, ptr, length uint32, payload []byte, marker byte) {
	t.Helper()
	got, ok := mod.Memory().Read(ptr, length)
	if !ok {
		t.Fatalf("read back guest memory at %d len %d", ptr, length)
	}
	if !bytes.Equal(got[:len(payload)], payload) {
		t.Fatalf("guest payload = %q, want %q", got[:len(payload)], payload)
	}
	want := bytes.Repeat([]byte{marker}, int(length)-len(payload))
	if !bytes.Equal(got[len(payload):], want) {
		t.Fatalf("guest bytes after payload were modified: %x", got[len(payload):])
	}
}

func assertCalls(t *testing.T, s *scriptedSocket, wantCalls int, wantBufLen int) {
	t.Helper()
	if s.calls != wantCalls {
		t.Fatalf("underlying Read calls = %d, want %d", s.calls, wantCalls)
	}
	for i, l := range s.bufLens {
		if l != wantBufLen {
			t.Fatalf("underlying Read %d buffer length = %d, want %d", i, l, wantBufLen)
		}
	}
}

func assertTrap(t *testing.T, trap error, wantIs error, wantSubstrings ...string) {
	t.Helper()
	if trap == nil {
		t.Fatal("expected a host trap, got none")
	}
	if wantIs != nil && !errors.Is(trap, wantIs) {
		t.Fatalf("trap %q does not wrap %q", trap, wantIs)
	}
	for _, sub := range wantSubstrings {
		if !strings.Contains(trap.Error(), sub) {
			t.Fatalf("trap %q does not mention %q", trap, sub)
		}
	}
}

var errSentinel = errors.New("scripted sentinel read failure")

const (
	guestPtr    = uint32(1024)
	guestLen    = uint32(16)
	guestMarker = byte(0xEE)
)

var streamTypes = []struct {
	name string
	typ  socket.SocketType
}{
	{"TCP", socket.SocketTypeTCP},
	{"TLS", socket.SocketTypeTLS},
}

// TestHostReceiveDataStream covers the TCP/TLS rows of the shared contract
// table for a single host call.
func TestHostReceiveDataStream(t *testing.T) {
	cases := []struct {
		name        string
		result      readResult
		wantN       int32
		wantPayload []byte
		wantTrapIs  error
		wantTrapMsg []string
	}{
		{
			name:        "short data",
			result:      readResult{data: []byte("abc"), n: 3},
			wantN:       3,
			wantPayload: []byte("abc"),
		},
		{
			name:        "data with EOF",
			result:      readResult{data: []byte("tail"), n: 4, err: io.EOF},
			wantN:       4,
			wantPayload: []byte("tail"),
		},
		{
			name:   "clean EOF",
			result: readResult{n: 0, err: io.EOF},
			wantN:  0,
		},
		{
			name:        "wrapped EOF with data",
			result:      readResult{data: []byte("xy"), n: 2, err: fmt.Errorf("fallback read: %w", io.EOF)},
			wantN:       2,
			wantPayload: []byte("xy"),
		},
		{
			name:   "wrapped clean EOF",
			result: readResult{n: 0, err: fmt.Errorf("fallback read: %w", io.EOF)},
			wantN:  0,
		},
		{
			name:        "sentinel error",
			result:      readResult{n: 0, err: errSentinel},
			wantTrapIs:  errSentinel,
			wantTrapMsg: []string{"receive_data: read error:", errSentinel.Error()},
		},
		{
			name:        "data with sentinel error still traps",
			result:      readResult{data: []byte("abc"), n: 3, err: errSentinel},
			wantTrapIs:  errSentinel,
			wantTrapMsg: []string{"receive_data: read error:"},
		},
		{
			name:        "no progress (0,nil) is rejected",
			result:      readResult{n: 0},
			wantTrapIs:  io.ErrNoProgress,
			wantTrapMsg: []string{"receive_data: read error:", "no progress"},
		},
	}

	for _, st := range streamTypes {
		for _, tc := range cases {
			t.Run(st.name+"/"+tc.name, func(t *testing.T) {
				mod := newGuestModule(t)
				fillGuest(t, mod, guestPtr, guestLen, guestMarker)

				env := newReceiveEnv()
				sock := &scriptedSocket{typ: st.typ, results: []readResult{tc.result}}
				handle, addErr := env.Registry.Add(sock)
				if addErr != nil {
					t.Fatal(addErr)
				}

				n, trap := callReceive(HostReceiveData(env), mod, handle, guestPtr, guestLen)

				assertCalls(t, sock, 1, int(guestLen))
				if tc.wantTrapIs != nil {
					assertTrap(t, trap, tc.wantTrapIs, tc.wantTrapMsg...)
					return
				}
				if trap != nil {
					t.Fatalf("unexpected trap: %v", trap)
				}
				if n != tc.wantN {
					t.Fatalf("count = %d, want %d", n, tc.wantN)
				}
				assertGuest(t, mod, guestPtr, guestLen, tc.wantPayload, guestMarker)
			})
		}
	}
}

// TestHostReceiveDataStreamEOFSequence checks that data delivered together
// with EOF is followed by a plain 0 on the next call, which is how the guest
// observes the end of stream.
func TestHostReceiveDataStreamEOFSequence(t *testing.T) {
	for _, st := range streamTypes {
		t.Run(st.name, func(t *testing.T) {
			mod := newGuestModule(t)
			fillGuest(t, mod, guestPtr, guestLen, guestMarker)

			env := newReceiveEnv()
			sock := &scriptedSocket{typ: st.typ, results: []readResult{
				{data: []byte("last"), n: 4, err: io.EOF},
				{n: 0, err: io.EOF},
				{n: 0, err: io.EOF},
			}}
			handle, addErr := env.Registry.Add(sock)
			if addErr != nil {
				t.Fatal(addErr)
			}
			recv := HostReceiveData(env)

			n, trap := callReceive(recv, mod, handle, guestPtr, guestLen)
			if trap != nil || n != 4 {
				t.Fatalf("first call = (%d, %v), want (4, nil)", n, trap)
			}
			assertGuest(t, mod, guestPtr, guestLen, []byte("last"), guestMarker)

			for i := 2; i <= 3; i++ {
				n, trap = callReceive(recv, mod, handle, guestPtr, guestLen)
				if trap != nil || n != 0 {
					t.Fatalf("call %d = (%d, %v), want (0, nil)", i, n, trap)
				}
			}
			// The bytes from the first read stay intact through repeated EOF.
			assertGuest(t, mod, guestPtr, guestLen, []byte("last"), guestMarker)
			assertCalls(t, sock, 3, int(guestLen))
		})
	}
}

// TestHostReceiveDataStreamEmptyBuffer documents that the no-progress trap is
// bounded to nonempty buffers: a zero-length host read returning (0,nil) is
// simply 0.
func TestHostReceiveDataStreamEmptyBuffer(t *testing.T) {
	for _, st := range streamTypes {
		t.Run(st.name, func(t *testing.T) {
			mod := newGuestModule(t)
			env := newReceiveEnv()
			sock := &scriptedSocket{typ: st.typ, results: []readResult{{n: 0}}}
			handle, addErr := env.Registry.Add(sock)
			if addErr != nil {
				t.Fatal(addErr)
			}

			n, trap := callReceive(HostReceiveData(env), mod, handle, guestPtr, 0)
			if trap != nil || n != 0 {
				t.Fatalf("empty read = (%d, %v), want (0, nil)", n, trap)
			}
			assertCalls(t, sock, 1, 0)
		})
	}
}

// TestHostReceiveDataDatagram covers the UDP/ICMP rows: an empty datagram is
// a legitimate 0 and EOF is not normalized.
func TestHostReceiveDataDatagram(t *testing.T) {
	types := []struct {
		name string
		typ  socket.SocketType
	}{
		{"UDP", socket.SocketTypeUDP},
		{"ICMP4", socket.SocketTypeICMP4},
	}
	cases := []struct {
		name        string
		result      readResult
		wantN       int32
		wantPayload []byte
		wantTrapIs  error
		wantTrapMsg []string
	}{
		{
			name:   "zero-length datagram",
			result: readResult{n: 0},
			wantN:  0,
		},
		{
			name:        "datagram payload",
			result:      readResult{data: []byte("ping"), n: 4},
			wantN:       4,
			wantPayload: []byte("ping"),
		},
		{
			name:        "EOF traps",
			result:      readResult{n: 0, err: io.EOF},
			wantTrapIs:  io.EOF,
			wantTrapMsg: []string{"receive_data: read error: EOF"},
		},
		{
			name:        "wrapped EOF traps",
			result:      readResult{n: 0, err: fmt.Errorf("fallback read: %w", io.EOF)},
			wantTrapIs:  io.EOF,
			wantTrapMsg: []string{"receive_data: read error:"},
		},
		{
			name:        "sentinel error traps",
			result:      readResult{n: 0, err: errSentinel},
			wantTrapIs:  errSentinel,
			wantTrapMsg: []string{"receive_data: read error:"},
		},
	}

	for _, dt := range types {
		for _, tc := range cases {
			t.Run(dt.name+"/"+tc.name, func(t *testing.T) {
				mod := newGuestModule(t)
				fillGuest(t, mod, guestPtr, guestLen, guestMarker)

				env := newReceiveEnv()
				sock := &scriptedSocket{typ: dt.typ, results: []readResult{tc.result}}
				handle, addErr := env.Registry.Add(sock)
				if addErr != nil {
					t.Fatal(addErr)
				}

				n, trap := callReceive(HostReceiveData(env), mod, handle, guestPtr, guestLen)

				assertCalls(t, sock, 1, int(guestLen))
				if tc.wantTrapIs != nil {
					assertTrap(t, trap, tc.wantTrapIs, tc.wantTrapMsg...)
					return
				}
				if trap != nil {
					t.Fatalf("unexpected trap: %v", trap)
				}
				if n != tc.wantN {
					t.Fatalf("count = %d, want %d", n, tc.wantN)
				}
				assertGuest(t, mod, guestPtr, guestLen, tc.wantPayload, guestMarker)
			})
		}
	}
}

// TestHostReceiveDataInvalidHandle preserves the trap for unknown and closed
// handles; no socket read happens.
func TestHostReceiveDataInvalidHandle(t *testing.T) {
	mod := newGuestModule(t)

	t.Run("unknown handle", func(t *testing.T) {
		env := newReceiveEnv()
		_, trap := callReceive(HostReceiveData(env), mod, 5, guestPtr, guestLen)
		assertTrap(t, trap, nil, "receive_data:", "invalid socket handle 5")
	})

	t.Run("negative handle", func(t *testing.T) {
		env := newReceiveEnv()
		_, trap := callReceive(HostReceiveData(env), mod, -1, guestPtr, guestLen)
		assertTrap(t, trap, nil, "receive_data:", "invalid socket handle -1")
	})

	t.Run("closed handle", func(t *testing.T) {
		env := newReceiveEnv()
		sock := &scriptedSocket{typ: socket.SocketTypeTCP, results: []readResult{{data: []byte("abc"), n: 3}}}
		handle, addErr := env.Registry.Add(sock)
		if addErr != nil {
			t.Fatal(addErr)
		}
		if err := env.Registry.Close(handle); err != nil {
			t.Fatalf("close handle: %v", err)
		}
		_, trap := callReceive(HostReceiveData(env), mod, handle, guestPtr, guestLen)
		assertTrap(t, trap, nil, "receive_data:", "has been closed")
		assertCalls(t, sock, 0, 0)
	})
}

// TestHostReceiveDataInvalidMemory preserves the out-of-bounds trap before any
// socket read, and the 8192-element clamp on the requested length.
func TestHostReceiveDataInvalidMemory(t *testing.T) {
	cases := []struct {
		name string
		ptr  uint32
		len  uint32
	}{
		{"pointer past end", wasmPageSize, 1},
		{"range crosses end", wasmPageSize - 4, 16},
		{"pointer wraps", 0xFFFFFFF0, 32},
	}
	for _, st := range streamTypes {
		for _, tc := range cases {
			t.Run(st.name+"/"+tc.name, func(t *testing.T) {
				mod := newGuestModule(t)
				env := newReceiveEnv()
				sock := &scriptedSocket{typ: st.typ, results: []readResult{{data: []byte("abc"), n: 3}}}
				handle, addErr := env.Registry.Add(sock)
				if addErr != nil {
					t.Fatal(addErr)
				}

				_, trap := callReceive(HostReceiveData(env), mod, handle, tc.ptr, tc.len)
				assertTrap(t, trap, nil, "out of memory bounds", fmt.Sprintf("pointer %d", tc.ptr))
				assertCalls(t, sock, 0, 0)
			})
		}
	}

	t.Run("length clamped to MAX_SLICE_LENGTH", func(t *testing.T) {
		mod := newGuestModule(t)
		env := newReceiveEnv()
		sock := &scriptedSocket{typ: socket.SocketTypeTCP, results: []readResult{{data: []byte("abc"), n: 3}}}
		handle, addErr := env.Registry.Add(sock)
		if addErr != nil {
			t.Fatal(addErr)
		}

		n, trap := callReceive(HostReceiveData(env), mod, handle, 0, 3*MAX_SLICE_LENGTH)
		if trap != nil || n != 3 {
			t.Fatalf("clamped read = (%d, %v), want (3, nil)", n, trap)
		}
		assertCalls(t, sock, 1, MAX_SLICE_LENGTH)
	})
}
