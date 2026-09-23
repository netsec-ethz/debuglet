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

package debuglet

// This file deliberately has no _wasm_test.go suffix and no build tag: it is a
// native test that builds the real wasip1 SDK into a guest and executes it.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

const (
	guestBuildTimeout = 90 * time.Second
	guestRunTimeout   = 20 * time.Second

	// guestBufSize must match bufSize in testdata/read_contract/main.go.
	guestBufSize = 16

	// Handles returned by the scripted connect/accept imports. Distinct values
	// let the script check that Read passes the handle it was given.
	handleTCP    int32 = 7
	handleTLS    int32 = 11
	handleAccept int32 = 13
	handleUDP    int32 = 17
	handleICMP   int32 = 19
)

// recvResult is one scripted result of a receive import: count is returned to
// the guest and data (if any) is written to the guest buffer first.
type recvResult struct {
	count int32
	data  []byte
}

// hostScript is the scripted "env" module for one guest run. It records every
// call so the test can assert exactly which imports were invoked.
type hostScript struct {
	tcpRecv  []recvResult
	udpRecv  []recvResult
	icmpRecv []recvResult

	calls map[string]int
	// failures collects script violations raised inside host calls. They are
	// reported by the test after the guest returns, so a violation cannot be
	// hidden by the guest's own output.
	failures []string
}

func newHostScript() *hostScript {
	return &hostScript{calls: map[string]int{}}
}

func (h *hostScript) fail(format string, args ...any) {
	h.failures = append(h.failures, fmt.Sprintf(format, args...))
}

func (h *hostScript) count(name string) { h.calls[name]++ }

// receive serves one scripted result. It validates the handle and the buffer
// length the SDK passed, then writes any payload into guest memory.
func (h *hostScript) receive(name string, wantHandle func() int32, script *[]recvResult) func(context.Context, api.Module, uint32, uint32, uint32) int32 {
	return func(_ context.Context, mod api.Module, sock, bufp, bufLen uint32) int32 {
		h.count(name)
		if want := wantHandle(); int32(sock) != want {
			h.fail("%s: handle %d, want %d", name, int32(sock), want)
		}
		if bufLen != guestBufSize {
			h.fail("%s: buffer length %d, want %d", name, bufLen, guestBufSize)
		}
		if len(*script) == 0 {
			h.fail("%s: unscripted call #%d", name, h.calls[name])
			return -1
		}
		res := (*script)[0]
		*script = (*script)[1:]
		if len(res.data) > 0 {
			if uint32(len(res.data)) > bufLen {
				h.fail("%s: script payload %d exceeds guest buffer %d", name, len(res.data), bufLen)
				return -1
			}
			if !mod.Memory().Write(bufp, res.data) {
				h.fail("%s: cannot write %d bytes at %#x", name, len(res.data), bufp)
				return -1
			}
		}
		return res.count
	}
}

func (h *hostScript) connect(name string, handle int32) func(context.Context, api.Module, uint32, uint32) int32 {
	return func(_ context.Context, mod api.Module, addrp, addrLen uint32) int32 {
		h.count(name)
		if addr, ok := mod.Memory().Read(addrp, addrLen); !ok || len(addr) == 0 {
			h.fail("%s: unreadable address (%#x,%d)", name, addrp, addrLen)
			return -1
		}
		return handle
	}
}

func (h *hostScript) closeFn(name string) func(context.Context, uint32) {
	return func(_ context.Context, _ uint32) { h.count(name) }
}

// unexpected records a call to an import the fixture never needs; any such
// call is a test failure.
func (h *hostScript) unexpected(name string) {
	h.count(name)
	h.fail("%s: unexpected host call", name)
}

// instantiate registers the "env" module. Every import declared in
// debuglet_wasip1.go is exported so that the module links; only the ones the
// fixture uses have behavior.
func (h *hostScript) instantiate(ctx context.Context, r wazero.Runtime) (api.Module, error) {
	b := r.NewHostModuleBuilder("env")
	// Used by the fixture.
	b.NewFunctionBuilder().WithFunc(h.connect("connect_tcp", handleTCP)).Export("connect_tcp")
	b.NewFunctionBuilder().WithFunc(h.connect("connect_tls", handleTLS)).Export("connect_tls")
	b.NewFunctionBuilder().WithFunc(h.connect("connect_udp", handleUDP)).Export("connect_udp")
	b.NewFunctionBuilder().WithFunc(h.connect("connect_icmp4", handleICMP)).Export("connect_icmp4")
	b.NewFunctionBuilder().WithFunc(func(context.Context) int32 { h.count("accept_tcp"); return handleAccept }).Export("accept_tcp")
	b.NewFunctionBuilder().WithFunc(h.receive("receive_tcp_data", h.expectedTCPHandle, &h.tcpRecv)).Export("receive_tcp_data")
	b.NewFunctionBuilder().WithFunc(h.receive("receive_udp_data", constHandle(handleUDP), &h.udpRecv)).Export("receive_udp_data")
	b.NewFunctionBuilder().WithFunc(h.receive("receive_icmp4_data", constHandle(handleICMP), &h.icmpRecv)).Export("receive_icmp4_data")
	b.NewFunctionBuilder().WithFunc(h.closeFn("close_tcp")).Export("close_tcp")
	b.NewFunctionBuilder().WithFunc(h.closeFn("close_icmp4")).Export("close_icmp4")
	// Declared by the SDK but never used by the fixture: fail if called.
	b.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32) int32 { h.unexpected("get_tcp_addr"); return -1 }).Export("get_tcp_addr")
	b.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32) int32 { h.unexpected("get_udp_addr"); return -1 }).Export("get_udp_addr")
	b.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32, uint32, uint32, uint32) int32 {
		h.unexpected("receive_udp_from")
		return -1
	}).Export("receive_udp_from")
	b.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32, uint32) { h.unexpected("send_udp_data") }).Export("send_udp_data")
	b.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32, uint32) { h.unexpected("send_tcp_data") }).Export("send_tcp_data")
	b.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32, uint32) { h.unexpected("send_icmp4_data") }).Export("send_icmp4_data")
	b.NewFunctionBuilder().WithFunc(func(context.Context, uint32) { h.unexpected("drain_connection") }).Export("drain_connection")
	b.NewFunctionBuilder().WithFunc(func(context.Context, uint32, uint32, uint32) int32 { h.unexpected("get_remote_addr"); return -1 }).Export("get_remote_addr")
	return b.Instantiate(ctx)
}

// expectedTCPHandle is the handle receive_tcp_data must see. It is resolved
// at call time, after the guest connected: TLS and accepted connections have
// their own handles so the test can prove they were routed to the TCP import.
func (h *hostScript) expectedTCPHandle() int32 {
	switch {
	case h.calls["connect_tls"] > 0:
		return handleTLS
	case h.calls["accept_tcp"] > 0:
		return handleAccept
	default:
		return handleTCP
	}
}

func constHandle(handle int32) func() int32 { return func() int32 { return handle } }

// readCase describes one guest run.
type readCase struct {
	name string
	// argv passed verbatim to the guest; its single element selects the case.
	arg string
	// Scripted receive results per import.
	tcp, udp, icmp []recvResult
	// wantLines are the exact stdout lines the guest must print.
	wantLines []string
	// wantCalls are asserted exactly for the listed imports; every receive
	// import not listed must have zero calls.
	wantCalls map[string]int
}

func TestSDKReadContractWASM(t *testing.T) {
	wasmPath := buildGuest(t, "read_contract")

	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithCloseOnContextDone(true))
	defer r.Close(ctx)

	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("read guest: %v", err)
	}
	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		t.Fatalf("compile guest: %v", err)
	}
	defer compiled.Close(ctx)

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		t.Fatalf("instantiate WASI: %v", err)
	}

	hello := []byte("hello")
	cases := []readCase{
		{
			name: "tcp_zero_is_eof",
			arg:  "tcp_zero",
			tcp:  []recvResult{{count: 0}},
			wantLines: []string{
				`read1 n=0 eof=true err=EOF data=""`,
			},
			wantCalls: map[string]int{"connect_tcp": 1, "receive_tcp_data": 1},
		},
		{
			name: "tcp_positive_then_eof",
			arg:  "tcp_positive_then_eof",
			tcp:  []recvResult{{count: int32(len(hello)), data: hello}, {count: 0}},
			wantLines: []string{
				`read1 n=5 eof=false err=nil data="hello"`,
				`read2 n=0 eof=true err=EOF data=""`,
			},
			wantCalls: map[string]int{"connect_tcp": 1, "receive_tcp_data": 2},
		},
		{
			name: "empty_reads_never_call_host",
			arg:  "empty_reads_only",
			wantLines: []string{
				`read1_nil n=0 eof=false err=nil data=""`,
				`read1_empty n=0 eof=false err=nil data=""`,
			},
			wantCalls: map[string]int{"connect_tcp": 1, "receive_tcp_data": 0},
		},
		{
			name: "empty_reads_after_eof_never_call_host",
			arg:  "empty_reads_after_eof",
			tcp:  []recvResult{{count: 0}},
			wantLines: []string{
				`read1_nil n=0 eof=false err=nil data=""`,
				`read1_empty n=0 eof=false err=nil data=""`,
				`read2 n=0 eof=true err=EOF data=""`,
				`read3_nil n=0 eof=false err=nil data=""`,
				`read3_empty n=0 eof=false err=nil data=""`,
			},
			wantCalls: map[string]int{"connect_tcp": 1, "receive_tcp_data": 1},
		},
		{
			name: "udp_zero_is_not_eof",
			arg:  "udp_zero",
			udp:  []recvResult{{count: 0}},
			wantLines: []string{
				`read1 n=0 eof=false err=nil data=""`,
			},
			wantCalls: map[string]int{"connect_udp": 1, "receive_udp_data": 1},
		},
		{
			name: "icmp_zero_is_not_eof",
			arg:  "icmp_zero",
			icmp: []recvResult{{count: 0}},
			wantLines: []string{
				`read1 n=0 eof=false err=nil data=""`,
			},
			wantCalls: map[string]int{"connect_icmp4": 1, "receive_icmp4_data": 1},
		},
		{
			name: "tls_routes_to_tcp_semantics",
			arg:  "tls_zero",
			tcp:  []recvResult{{count: 0}},
			wantLines: []string{
				`read1 n=0 eof=true err=EOF data=""`,
			},
			wantCalls: map[string]int{"connect_tls": 1, "connect_tcp": 0, "receive_tcp_data": 1},
		},
		{
			name: "accepted_tcp_routes_to_tcp_semantics",
			arg:  "accepted_tcp_zero",
			tcp:  []recvResult{{count: 0}},
			wantLines: []string{
				`read1 n=0 eof=true err=EOF data=""`,
			},
			wantCalls: map[string]int{"accept_tcp": 1, "connect_tcp": 0, "receive_tcp_data": 1},
		},
		{
			name: "tcp_negative_count_is_error",
			arg:  "tcp_negative",
			tcp:  []recvResult{{count: -1}},
			wantLines: []string{
				`read1 n=0 eof=false err=other data=""`,
			},
			wantCalls: map[string]int{"connect_tcp": 1, "receive_tcp_data": 1},
		},
		{
			name: "tcp_oversized_count_is_error",
			arg:  "tcp_oversized",
			tcp:  []recvResult{{count: guestBufSize + 1}},
			wantLines: []string{
				`read1 n=0 eof=false err=other data=""`,
			},
			wantCalls: map[string]int{"connect_tcp": 1, "receive_tcp_data": 1},
		},
		{
			name: "udp_oversized_count_is_error",
			arg:  "udp_oversized",
			udp:  []recvResult{{count: guestBufSize + 1}},
			wantLines: []string{
				`read1 n=0 eof=false err=other data=""`,
			},
			wantCalls: map[string]int{"connect_udp": 1, "receive_udp_data": 1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runGuestCase(t, r, compiled, tc)
		})
	}
}

// buildGuest compiles the named testdata fixture for wasip1 into a temporary
// directory and returns the binary path. Missing Go or a build failure fails
// the test.
func buildGuest(t *testing.T, name string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain required to build the guest fixture: %v", err)
	}
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	out := filepath.Join(t.TempDir(), name+".wasm")
	ctx, cancel := context.WithTimeout(context.Background(), guestBuildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-mod=readonly", "-buildvcs=false", "-o", out, "./testdata/"+name)
	cmd.Dir = pkgDir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest %s: %v\n%s", name, err, output)
	}
	return out
}

// runGuestCase instantiates the scripted host module and the guest for one
// case, then asserts stdout and the recorded host calls.
func runGuestCase(t *testing.T, r wazero.Runtime, compiled wazero.CompiledModule, tc readCase) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), guestRunTimeout)
	defer cancel()

	h := newHostScript()
	h.tcpRecv = append([]recvResult(nil), tc.tcp...)
	h.udpRecv = append([]recvResult(nil), tc.udp...)
	h.icmpRecv = append([]recvResult(nil), tc.icmp...)
	envMod, err := h.instantiate(ctx, r)
	if err != nil {
		t.Fatalf("instantiate env: %v", err)
	}
	defer envMod.Close(ctx)

	var stdout, stderr bytes.Buffer
	cfg := wazero.NewModuleConfig().
		WithName(tc.name).
		WithArgs(tc.arg).
		WithStdout(&stdout).
		WithStderr(&stderr)
	guest, err := r.InstantiateModule(ctx, compiled, cfg)
	if guest != nil {
		defer guest.Close(ctx)
	}
	if err != nil {
		var exitErr *sys.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("guest exited with code %d\nstdout:\n%s\nstderr:\n%s", exitErr.ExitCode(), stdout.String(), stderr.String())
		}
		t.Fatalf("guest run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	for _, f := range h.failures {
		t.Errorf("host script: %s", f)
	}

	got := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if strings.Join(got, "\n") != strings.Join(tc.wantLines, "\n") {
		t.Errorf("guest stdout mismatch\n got:\n%s\nwant:\n%s\nstderr:\n%s", indent(got), indent(tc.wantLines), stderr.String())
	}

	for name, want := range tc.wantCalls {
		if got := h.calls[name]; got != want {
			t.Errorf("host calls to %s = %d, want %d", name, got, want)
		}
	}
	for _, name := range []string{"receive_tcp_data", "receive_udp_data", "receive_icmp4_data"} {
		if _, listed := tc.wantCalls[name]; !listed && h.calls[name] != 0 {
			t.Errorf("unexpected %d call(s) to %s", h.calls[name], name)
		}
	}
	if n := len(h.tcpRecv) + len(h.udpRecv) + len(h.icmpRecv); n != 0 {
		t.Errorf("%d scripted receive result(s) left unconsumed", n)
	}
}

func indent(lines []string) string {
	return "  " + strings.Join(lines, "\n  ")
}
