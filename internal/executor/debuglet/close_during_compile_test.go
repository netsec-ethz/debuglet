// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
)

// manyTypesModule encodes a valid WASM module with n distinct function types
// and one empty function per type. Decoding, validation and type
// registration all grow with n, which keeps a compile running long enough to
// close the run meanwhile.
func manyTypesModule(n int) []byte {
	leb := func(b []byte, v int) []byte {
		for {
			c := byte(v & 0x7f)
			v >>= 7
			if v == 0 {
				return append(b, c)
			}
			b = append(b, c|0x80)
		}
	}
	section := func(out []byte, id byte, body []byte) []byte {
		return append(leb(append(out, id), len(body)), body...)
	}
	valueTypes := [4]byte{0x7f, 0x7e, 0x7d, 0x7c}
	types, funcs, code := leb(nil, n), leb(nil, n), leb(nil, n)
	for i := 0; i < n; i++ {
		// Eight parameters in base four give 65536 distinct signatures.
		types = append(types, 0x60, 8)
		for d, v := 0, i; d < 8; d, v = d+1, v/4 {
			types = append(types, valueTypes[v%4])
		}
		types = append(types, 0)
		funcs = leb(funcs, i)
		code = append(code, 2, 0, 0x0b)
	}
	out := []byte{0x00, 'a', 's', 'm', 1, 0, 0, 0}
	out = section(out, 1, types)
	out = section(out, 3, funcs)
	return section(out, 10, code)
}

func waitRuntimeTest(t *testing.T, deb *Debuglet, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		deb.mu.Lock()
		ok := ready()
		deb.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("initializer did not publish its runtime")
		}
		runtime.Gosched()
	}
}

func TestCloseDuringCompileReturnsClosure(t *testing.T) {
	module := manyTypesModule(20000)
	deb := &Debuglet{env: &wasm.WasmEnv{Logger: zap.NewNop().Sugar()}}
	done := make(chan struct{})
	var initErr error
	go func() { defer close(done); initErr = deb.InitRuntime(context.Background(), module) }()
	t.Cleanup(func() { joinRuntimeTest(t, done) })
	waitRuntimeTest(t, deb, func() bool { return deb.initializing })
	if err := deb.Close(context.Background()); err != nil {
		t.Fatalf("Close=%v", err)
	}
	joinRuntimeTest(t, done)
	if !errors.Is(initErr, net.ErrClosed) {
		t.Fatalf("initialization=%v", initErr)
	}
	if err := deb.Close(context.Background()); err != nil {
		t.Fatalf("repeat Close=%v", err)
	}
	// The initializer released the runtime on its way out.
	if _, err := deb.runtime.CompileModule(context.Background(), manyTypesModule(1)); err == nil {
		t.Fatal("runtime still open after the initializer returned")
	}
}

type countedRuntime struct {
	wazero.Runtime
	calls atomic.Int32
}

func (r *countedRuntime) Close(ctx context.Context) error {
	r.calls.Add(1)
	return r.Runtime.Close(ctx)
}

type countedCompiled struct {
	wazero.CompiledModule
	calls atomic.Int32
}

func (c *countedCompiled) Close(ctx context.Context) error {
	c.calls.Add(1)
	return c.CompiledModule.Close(ctx)
}

func TestCloseAfterInitializationReleasesOnce(t *testing.T) {
	deb := &Debuglet{env: &wasm.WasmEnv{Logger: zap.NewNop().Sugar()}}
	if err := deb.InitRuntime(context.Background(), manyTypesModule(20000)); err != nil {
		t.Fatalf("InitRuntime=%v", err)
	}
	deb.mu.Lock()
	rt := &countedRuntime{Runtime: deb.runtime}
	compiled := &countedCompiled{CompiledModule: deb.compiled}
	deb.runtime, deb.compiled = rt, compiled
	initializing := deb.initializing
	deb.mu.Unlock()
	if initializing {
		t.Fatal("initialization still marked in progress")
	}
	if err := deb.Close(context.Background()); err != nil {
		t.Fatalf("Close=%v", err)
	}
	if err := deb.Close(context.Background()); err != nil {
		t.Fatalf("repeat Close=%v", err)
	}
	if rt.calls.Load() != 1 || compiled.calls.Load() != 1 {
		t.Fatalf("runtime closes=%d compiled closes=%d", rt.calls.Load(), compiled.calls.Load())
	}
	if _, err := rt.CompileModule(context.Background(), manyTypesModule(1)); err == nil {
		t.Fatal("runtime still open after Close")
	}
}
