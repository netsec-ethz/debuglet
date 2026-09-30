// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
)

func TestMain(m *testing.M) { WorkerMain(); os.Exit(m.Run()) }

func TestWorkerBridgeBoundsAndCopies(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	original := []byte{1, 2, 3}
	done := make(chan error, 1)
	go func() {
		wire := bridge{b}
		kind, data, err := wire.read()
		if err == nil && (kind != frameRead || len(data) != 8 || u32(data) != 9 || u32(data[4:]) != 3) {
			err = errors.New("unexpected read")
		}
		if err == nil {
			err = wire.send(frameMemory, append([]byte{1}, original...))
		}
		done <- err
	}()
	memory := remoteMemory{bridge{a}}
	data, ok := memory.Read(9, 3)
	if !ok || !bytes.Equal(data, original) {
		t.Fatalf("read=%v,%v", data, ok)
	}
	data[0] = 8
	if original[0] != 1 {
		t.Fatal("read aliases owner")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok = memory.Read(0, wasm.MAX_SLICE_LENGTH+1); ok {
		t.Fatal("oversized read accepted")
	}
	if memory.Write(0, make([]byte, wasm.MAX_SLICE_LENGTH+1)) {
		t.Fatal("oversized write accepted")
	}
}

func TestWorkerArgumentBounds(t *testing.T) {
	want := []string{"hello", "", "world"}
	encoded, err := encodeWorkerArgs(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeWorkerArgs(encoded)
	if err != nil || len(got) != len(want) {
		t.Fatalf("decode=%v,%v", got, err)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatal(got)
		}
	}
	if _, err = encodeWorkerArgs([]string{string(make([]byte, workerArgsBytes))}); err == nil {
		t.Fatal("oversized args accepted")
	}
	if _, err = decodeWorkerArgs([]byte{1, 0, 0, 0}); err == nil {
		t.Fatal("missing arg accepted")
	}
}

func workerTestConfig(t *testing.T) isolation.Config {
	t.Helper()
	root := os.Getenv("DEBUGLET_TEST_CGROUP_ROOT")
	if root == "" {
		t.Skip("requires an explicitly delegated test cgroup root")
	}
	return isolation.Config{Profile: "shared", CgroupRoot: root, NodeMemoryBytes: 512 << 20, NodeCPUQuotaUS: 100000, NodePIDs: 128,
		ControlMemoryReserveBytes: 128 << 20, ControlCPUReserveUS: 25000,
		CompileMemoryBytes: 256 << 20, CompileCPUQuotaUS: 50000, CompileWallMS: 10000, CompileConcurrency: 1, CompileQueue: 1,
		RunMemoryBytes: 256 << 20, RunCPUQuotaUS: 50000, RunWallMS: 10000, WorkerPIDs: 64, MemoryPages: 1024}
}
func workerSupervisor(t *testing.T, cfg isolation.Config) *isolation.Supervisor {
	t.Helper()
	s, err := isolation.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}
func minimalWorker(t *testing.T, s *isolation.Supervisor) *Worker {
	t.Helper()
	d := &Debuglet{env: &wasm.WasmEnv{}}
	w := NewWorker(d, s)
	t.Cleanup(func() {
		if err := w.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return w
}
func awaitWorker(t *testing.T, p *isolation.Process) {
	t.Helper()
	if p == nil {
		t.Fatal("worker was never started")
	}
	select {
	case <-p.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("worker was not reaped")
	}
}
func workerModule(body []byte) []byte {
	// A single memory and _start function. Fixtures make ordinary, bounded calls.
	module := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	leb := func(n int) []byte {
		var b []byte
		for {
			v := byte(n & 127)
			n >>= 7
			if n != 0 {
				v |= 128
			}
			b = append(b, v)
			if n == 0 {
				return b
			}
		}
	}
	section := func(id byte, data []byte) {
		module = append(module, id)
		module = append(module, leb(len(data))...)
		module = append(module, data...)
	}
	section(1, []byte{1, 96, 0, 0})
	section(3, []byte{1, 0})
	section(5, []byte{1, 0, 1})
	section(7, []byte{2, 6, '_', 's', 't', 'a', 'r', 't', 0, 0, 6, 'm', 'e', 'm', 'o', 'r', 'y', 2, 0})
	function := append([]byte{0}, body...)
	function = append(function, 11)
	code := append([]byte{1}, leb(len(function))...)
	section(10, append(code, function...))
	return module
}
func TestSharedWorkerLimitsAndDisposal(t *testing.T) {
	cfg := workerTestConfig(t)
	cfg.MemoryPages = 2
	s := workerSupervisor(t, cfg)
	t.Run("memory_growth", func(t *testing.T) {
		w := minimalWorker(t, s)
		// The first page fits; the second exceeds the two-page product limit.
		body := []byte{65, 1, 64, 0, 26, 65, 1, 64, 0, 65, 127, 71, 4, 64, 0, 11}
		if err := w.InitRuntime(t.Context(), workerModule(body)); err != nil {
			t.Fatal(err)
		}
		output := make(chan []byte, 1)
		if err := w.Run(t.Context(), output, nil); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		awaitWorker(t, w.process)
		if err := w.Run(t.Context(), make(chan []byte), nil); err == nil {
			t.Fatal("closed worker ran again")
		}
	})
	t.Run("ordinary_invalid_module", func(t *testing.T) {
		w := minimalWorker(t, s)
		err := w.InitRuntime(t.Context(), []byte("not a module"))
		var compile *CompileError
		if !errors.As(err, &compile) {
			t.Fatalf("compile result=%v", err)
		}
		awaitWorker(t, w.process)
		if err = w.Run(t.Context(), make(chan []byte), nil); err == nil {
			t.Fatal("failed compiler started guest")
		}
	})
	t.Run("unsupported_imports", func(t *testing.T) {
		for _, name := range []string{"missing_call", "connect_tcp"} {
			// Both declare an empty signature: one name is absent, and one known
			// host function has a different signature. Neither may reach Run.
			module := unavailableImportModule(name)
			w := minimalWorker(t, s)
			err := w.InitRuntime(t.Context(), module)
			var compile *CompileError
			if !errors.As(err, &compile) {
				t.Fatalf("import %s result=%v", name, err)
			}
			awaitWorker(t, w.process)
		}
	})
	t.Run("close_before_init", func(t *testing.T) {
		w := minimalWorker(t, s)
		if err := w.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := w.InitRuntime(t.Context(), workerModule(nil)); err == nil {
			t.Fatal("closed worker initialized")
		}
	})
}
func TestSharedCompilerAdmissionAndJoin(t *testing.T) {
	s := workerSupervisor(t, workerTestConfig(t))
	parent, child, err := workerPair()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	defer child.Close()
	held, err := s.Start(t.Context(), child, workerArgument)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	// A child awaiting its module owns the compilation seat. Observe the
	// second caller entering its context-select, then verify the queue is full.
	ctx, cancel := context.WithCancel(t.Context())
	waiting := &compilerWaitContext{Context: ctx, entered: make(chan struct{})}
	queued := make(chan error, 1)
	go func() {
		p, err := s.Start(waiting, child, workerArgument)
		if p != nil {
			_ = p.Close()
		}
		queued <- err
	}()
	select {
	case <-waiting.entered:
	case <-time.After(time.Second):
		t.Fatal("compiler did not enter queue")
	}
	if _, err = s.Start(t.Context(), child, workerArgument); !errors.Is(err, isolation.ErrAdmission) {
		t.Fatalf("full compiler queue=%v", err)
	}
	cancel()
	if err = <-queued; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation=%v", err)
	}
	select {
	case <-held.Done():
		t.Fatal("queued cancellation disposed the active compiler")
	default:
	}
	held.Compiled() // phase completion releases compilation capacity, not memory.
	second, err := s.Start(t.Context(), child, workerArgument)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.Compiled()
	if _, err = s.Start(t.Context(), child, workerArgument); !errors.Is(err, isolation.ErrAdmission) {
		t.Fatalf("node memory admission=%v", err)
	}
	if err = held.Close(); err != nil {
		t.Fatal(err)
	}
	awaitWorker(t, held)
	if err = held.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := s.Start(t.Context(), child, workerArgument)
	if err != nil {
		t.Fatal(err)
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
	awaitWorker(t, replacement)
}
func TestSharedWorkerCancellationAndSibling(t *testing.T) {
	cfg := workerTestConfig(t)
	cfg.RunWallMS = 50
	s := workerSupervisor(t, cfg)
	w := minimalWorker(t, s)
	// A finite arithmetic loop, with 10 million iterations, exercises the wall
	// budget under a fractional CPU quota without a host pressure workload.
	body := []byte{65, 128, 173, 226, 4, 33, 0, 3, 64, 32, 0, 65, 1, 107, 34, 0, 13, 0, 11}
	module := workerModule(body)
	// Replace the single function's zero local count by one i32 local.
	pos := bytes.LastIndex(module, []byte{0, 65, 128, 173, 226, 4})
	if pos < 0 {
		t.Fatal("fixture code missing")
	}
	// The small fixed code section length and function length remain one byte.
	module[pos-3] += 2
	module[pos-1] += 2
	module = append(module[:pos], append([]byte{1, 1, 127}, module[pos+1:]...)...)
	if err := w.InitRuntime(t.Context(), module); err != nil {
		t.Fatal(err)
	}
	err := w.Run(t.Context(), make(chan []byte), nil)
	if !errors.Is(err, isolation.ErrExecutionBudget) {
		t.Fatalf("run budget=%v", err)
	}
	if err := w.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitWorker(t, w.process)
	sibling := minimalWorker(t, s)
	if err := sibling.InitRuntime(t.Context(), workerModule(nil)); err != nil {
		t.Fatal(err)
	}
	if err := sibling.Run(t.Context(), make(chan []byte), nil); err != nil {
		t.Fatal("healthy sibling:", err)
	}
}

func TestSharedCompilerDeadlineDisposesWorker(t *testing.T) {
	cfg := workerTestConfig(t)
	cfg.CompileWallMS = 250
	s := workerSupervisor(t, cfg)
	ordinary, err := os.ReadFile("../../../pkg/debuglet/testdata/abi_v1/abi_v1.wasm")
	if err != nil {
		t.Fatal(err)
	}
	w := minimalWorker(t, s)
	err = w.InitRuntime(t.Context(), ordinary)
	if !errors.Is(err, isolation.ErrCompileBudget) {
		t.Fatalf("compiler wall budget=%v", err)
	}
	awaitWorker(t, w.process)
	if err = w.Run(t.Context(), make(chan []byte), nil); err == nil {
		t.Fatal("expired compiler started a guest")
	}
	sibling := minimalWorker(t, s)
	if err = sibling.InitRuntime(t.Context(), workerModule(nil)); err != nil {
		t.Fatal("healthy compiler:", err)
	}
	if err = sibling.Run(t.Context(), make(chan []byte), nil); err != nil {
		t.Fatal(err)
	}
}

func TestSharedWorkerKernelMemoryBudget(t *testing.T) {
	cfg := workerTestConfig(t)
	cfg.MemoryPages = 16
	cfg.RunMemoryBytes = 1 << 20
	s := workerSupervisor(t, cfg)
	w := minimalWorker(t, s)
	// One bounded 1MiB WASM memory.fill charges guest pages after the phase
	// transition. Only this owned child has a deliberately tiny kernel limit.
	body := []byte{65, 15, 64, 0, 26, 65, 0, 65, 1, 65, 128, 128, 192, 0, 252, 11, 0}
	if err := w.InitRuntime(t.Context(), workerModule(body)); err != nil {
		t.Fatal(err)
	}
	err := w.Run(t.Context(), make(chan []byte), nil)
	if !errors.Is(err, isolation.ErrExecutionBudget) {
		t.Fatalf("kernel budget=%v", err)
	}
	awaitWorker(t, w.process)
	if !w.process.BudgetExceeded() {
		t.Fatal("no kernel memory-limit event")
	}
}

func TestWorkerCloseCancelsHostPhaseAndObservesLateCleanup(t *testing.T) {
	w := NewWorker(&Debuglet{env: &wasm.WasmEnv{}}, nil)
	phase, cancel := context.WithCancelCause(t.Context())
	w.runCancel = cancel
	if err := w.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(context.Cause(phase), net.ErrClosed) {
		t.Fatal("direct close left host-call context active")
	}
	late := errors.New("late network resource cleanup")
	w.env.RecordCleanupError(late)
	if err := w.Close(t.Context()); !errors.Is(err, late) {
		t.Fatalf("late cleanup=%v", err)
	}
}

type compilerWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *compilerWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func unavailableImportModule(name string) []byte {
	module := []byte{0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0}
	imported := append([]byte{1, 3, 'e', 'n', 'v', byte(len(name))}, []byte(name)...)
	imported = append(imported, 0, 0)
	module = append(module, 2, byte(len(imported)))
	return append(module, imported...)
}

func TestWorkerRejectsUnavailableImports(t *testing.T) {
	for _, name := range []string{"missing_call", "connect_tcp"} {
		t.Run(name, func(t *testing.T) {
			parent, child := net.Pipe()
			defer parent.Close()
			defer child.Close()
			if err := parent.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- serveWorker(bridge{child}) }()
			b := bridge{parent}
			module := unavailableImportModule(name)
			if err := b.send(frameInit, append32(append32(nil, uint32(len(module))), 2)); err != nil {
				t.Fatal(err)
			}
			if err := b.blob(module); err != nil {
				t.Fatal(err)
			}
			kind, data, err := b.read()
			if err != nil || kind != frameCompiled || !bytes.Equal(data, []byte{1}) {
				t.Fatalf("compile rejection=%d,%v,%v", kind, data, err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedWorkerRejectsInvalidMemoryRanges(t *testing.T) {
	s := workerSupervisor(t, workerTestConfig(t))
	for _, length := range []byte{1, 2} {
		// A real guest asks for one or two bytes starting exactly at the end of
		// its one-page memory. The host must reject the range before any dial.
		module := []byte{0, 97, 115, 109, 1, 0, 0, 0,
			1, 10, 2, 96, 2, 127, 127, 1, 127, 96, 0, 0,
			2, 19, 1, 3, 'e', 'n', 'v', 11, 'c', 'o', 'n', 'n', 'e', 'c', 't', '_', 't', 'c', 'p', 0, 0,
			3, 2, 1, 1,
			5, 3, 1, 0, 1,
			7, 19, 2, 6, '_', 's', 't', 'a', 'r', 't', 0, 1, 6, 'm', 'e', 'm', 'o', 'r', 'y', 2, 0,
			10, 13, 1, 11, 0, 65, 128, 128, 4, 65, length, 16, 0, 26, 11}
		w := minimalWorker(t, s)
		if err := w.InitRuntime(t.Context(), module); err != nil {
			t.Fatal(err)
		}
		if err := w.Run(t.Context(), make(chan []byte), nil); err == nil || !strings.Contains(err.Error(), "out of memory bounds") {
			t.Fatalf("memory range rejection=%v", err)
		}
		if err := w.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		awaitWorker(t, w.process)
	}
	sibling := minimalWorker(t, s)
	if err := sibling.InitRuntime(t.Context(), workerModule(nil)); err != nil {
		t.Fatal(err)
	}
	if err := sibling.Run(t.Context(), make(chan []byte), nil); err != nil {
		t.Fatal("healthy sibling:", err)
	}
}
