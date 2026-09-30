// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	host "github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"go.uber.org/zap"
)

const recoverableGuest = "./pkg/debuglet/testdata/recoverable_io"

type recoverableScript struct {
	reads, writes int
	datagram      bool
}

func (s *recoverableScript) Read(b []byte) (int, error) {
	s.reads++
	if s.datagram {
		return 0, nil
	}
	if s.reads == 1 {
		return copy(b, "abc"), syscall.ECONNRESET
	}
	return copy(b, "ok"), io.EOF
}
func (s *recoverableScript) Write(b []byte) (int, error) {
	s.writes++
	if s.datagram {
		return len(b), nil
	}
	if s.writes == 1 {
		return 2, os.ErrDeadlineExceeded
	}
	return len(b), nil
}
func (*recoverableScript) Close() error { return nil }
func (s *recoverableScript) Type() socket.SocketType {
	if s.datagram {
		return socket.SocketTypeUDP
	}
	return socket.SocketTypeTCP
}
func (*recoverableScript) Addr() string       { return "127.0.0.1" }
func (*recoverableScript) RemoteAddr() string { return "127.0.0.1:1" }

func TestRecoverableGuestIOContract(t *testing.T) {
	wasm := buildGuest(t, recoverableGuest)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		t.Fatal(err)
	}
	compiled, err := r.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Close(ctx)
	wantImports := map[string]abiFunction{
		"dial":     {append(i32(3), api.ValueTypeI64), []api.ValueType{api.ValueTypeI64}},
		"read":     {i32(3), []api.ValueType{api.ValueTypeI64}},
		"write":    {i32(3), []api.ValueType{api.ValueTypeI64}},
		"close":    {i32(1), []api.ValueType{api.ValueTypeI64}},
		"deadline": {append(i32(2), api.ValueTypeI64), []api.ValueType{api.ValueTypeI64}},
	}
	for _, fn := range compiled.ImportedFunctions() {
		module, name, _ := fn.Import()
		if module != guestio.Module {
			continue
		}
		want, ok := wantImports[name]
		if !ok || !sameTypes(fn.ParamTypes(), want.params) || !sameTypes(fn.ResultTypes(), want.results) {
			t.Fatalf("extension signature changed: %s", name)
		}
		delete(wantImports, name)
	}
	if len(wantImports) != 0 {
		t.Fatalf("uncovered imports: %v", wantImports)
	}
	// An older host fails to link before guest code runs, naming the extension.
	if _, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig()); err == nil || !strings.Contains(err.Error(), guestio.Module) {
		t.Fatalf("missing extension error: %v", err)
	}
	budget := socket.NewBudget(socket.DefaultLimits(), socket.NewDescriptorBudget(socket.DefaultNodeDescriptors))
	env := &host.WasmEnv{Budget: budget, Registry: socket.NewSocketRegistry(budget), Logger: zap.NewNop().Sugar()}
	script := new(recoverableScript)
	handle, err := env.Registry.Add(script)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Registry.CloseAll()
	_, err = r.NewHostModuleBuilder(guestio.Module).
		NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, int64) uint64 { return uint64(handle) }).Export("dial").
		NewFunctionBuilder().WithFunc(host.HostIORead(env)).Export("read").
		NewFunctionBuilder().WithFunc(host.HostIOWrite(env)).Export("write").
		NewFunctionBuilder().WithFunc(host.HostIOClose(env)).Export("close").
		NewFunctionBuilder().WithFunc(host.HostIODeadline(env)).Export("deadline").Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, err = r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithStdout(&out).WithStderr(&out).WithArgs("scripted", "127.0.0.1:1"))
	if err != nil || !strings.Contains(out.String(), "guest continues") {
		t.Fatalf("guest: %v; %s", err, &out)
	}
	if script.reads != 2 || script.writes != 2 {
		t.Fatalf("reads=%d writes=%d", script.reads, script.writes)
	}
	script = &recoverableScript{datagram: true}
	handle, err = env.Registry.Add(script)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_, err = r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithStdout(&out).WithStderr(&out).WithArgs("datagram", "127.0.0.1:1"))
	if err != nil || !strings.Contains(out.String(), "guest continues") {
		t.Fatalf("datagram guest: %v; %s", err, &out)
	}
	if script.reads != 1 || script.writes != 2 {
		t.Fatalf("datagram calls: reads=%d writes=%d", script.reads, script.writes)
	}
}

func TestRecoverableGuestRealTransports(t *testing.T) {
	wasm := buildGuest(t, recoverableGuest)
	for _, mode := range []string{"deadline", "reset", "refused", "connect-timeout", "connect-reset", "denied", "datagram"} {
		t.Run(mode, func(t *testing.T) {
			addr := closedTCPAddr(t)
			datagrams := make(chan int, 2)
			if mode == "datagram" {
				addr = startUDPTarget(t, func(data []byte) []byte {
					datagrams <- len(data)
					if len(data) == 0 {
						return []byte{}
					}
					return nil
				})
			}
			if mode == "deadline" {
				addr = startTCPTarget(t, func(c net.Conn) {
					var buf [4]byte
					if _, err := io.ReadFull(c, buf[:]); err == nil && string(buf[:]) == "PING" {
						_, _ = c.Write([]byte("PONG"))
					}
				})
			} else if mode == "reset" || mode == "connect-reset" {
				addr = startTCPTarget(t, func(c net.Conn) { _ = c.(*net.TCPConn).SetLinger(0) })
			} else if mode == "connect-timeout" {
				addr = startTCPTarget(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
			}
			addresses := []string{loopback}
			if mode == "denied" {
				addresses = []string{"127.0.0.2"}
			}
			g := runGuest(t, wasm, hostOptions{addresses: addresses, args: []string{mode, addr}})
			if err := g.err(); err != nil {
				t.Fatalf("guest failed: %v; %s", err, g.output())
			}
			requireContains(t, g, "handled "+mode)
			if mode == "datagram" {
				if first, second := <-datagrams, <-datagrams; first != 4 || second != 0 {
					t.Fatalf("datagram lengths: %d, %d", first, second)
				}
			}
		})
	}
}
