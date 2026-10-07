// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"slices"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/tetratelabs/wazero"
	wasi "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// WorkerMain dispatches the executor's private inherited-descriptor mode before
// normal configuration or credentials are loaded. It opens no network listener.
// Tests use the identical entry point in their test executable.
func WorkerMain() {
	if len(os.Args) != 2 || (os.Args[1] != workerArgument && os.Args[1] != workerArgument+"-entered") {
		return
	}
	file := os.NewFile(3, "guest-parent")
	if file == nil {
		os.Exit(2)
	}
	if os.Args[1] == workerArgument {
		if err := restrictWorker(); err != nil {
			os.Exit(2)
		}
		return // successful restriction execs a fresh capability-free process
	}
	if err := verifyWorkerParent(); err != nil {
		os.Exit(2)
	}
	if err := serveWorker(bridge{file}); err != nil {
		_ = file.Close()
		os.Exit(2)
	}
	_ = file.Close()
	os.Exit(0)
}

func serveWorker(b bridge) error {
	ctx := context.Background()
	kind, header, err := b.read()
	if err != nil {
		return err
	}
	if kind != frameInit || len(header) != 8 || u32(header[4:]) == 0 || u32(header[4:]) > 65536 {
		return errors.New("invalid worker initialization")
	}
	module, err := b.receiveBlob(u32(header), workerModuleBytes)
	if err != nil {
		return err
	}
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithMemoryLimitPages(u32(header[4:])).WithCloseOnContextDone(true))
	defer rt.Close(ctx)
	compiled, err := rt.CompileModule(ctx, module)
	module = nil
	if err != nil {
		return b.send(frameCompiled, []byte{1})
	}
	defer compiled.Close(ctx)
	if _, err = wasi.Instantiate(ctx, rt); err != nil {
		return b.send(frameCompiled, []byte{1})
	}
	functions := wasm.Functions(nil)
	for _, moduleName := range []string{"env", guestio.Module, wasm.ExperimentModule} {
		if _, err = wasm.Register(rt.NewHostModuleBuilder(moduleName), moduleName, functions, b.proxy).Instantiate(ctx); err != nil {
			return b.send(frameCompiled, []byte{1})
		}
	}
	if !workerImportsAvailable(rt, compiled) {
		return b.send(frameCompiled, []byte{1})
	}
	if err = b.send(frameCompiled, []byte{0}); err != nil {
		return err
	}
	kind, header, err = b.read()
	if err != nil {
		return err
	}
	if kind != frameRun || len(header) != 4 {
		return errors.New("invalid worker start")
	}
	data, err := b.receiveBlob(u32(header), workerArgsBytes)
	if err != nil {
		return err
	}
	args, err := decodeWorkerArgs(data)
	if err != nil {
		return err
	}
	data = nil
	writer := &workerWriter{bridge: b}
	cfg := wazero.NewModuleConfig().WithStdout(writer).WithStderr(writer).WithSysWalltime().WithSysNanotime().WithSysNanosleep().WithRandSource(rand.Reader).WithArgs(args...)
	mod, err := rt.InstantiateModule(ctx, compiled, cfg)
	if mod != nil {
		err = errors.Join(err, mod.Close(ctx))
	}
	if writer.err != nil {
		return writer.err
	}
	result := []byte{0}
	if err != nil {
		var exit *sys.ExitError
		if errors.As(err, &exit) {
			result = []byte{2}
			result = append32(result, exit.ExitCode())
		} else {
			result = []byte{1}
		}
	}
	return b.send(frameResult, result)
}

type workerWriter struct {
	bridge
	err error
}

func (w *workerWriter) Write(data []byte) (int, error) {
	accepted := 0
	for len(data) > 0 {
		n := min(len(data), bridgeFrame)
		if err := w.send(frameOutput, data[:n]); err != nil {
			w.err = err
			return accepted, err
		}
		// The acknowledgement couples WASI progress to durable-output backpressure.
		kind, result, err := w.read()
		if err != nil || kind != frameReturn || len(result) != 0 {
			w.err = io.ErrClosedPipe
			return accepted, w.err
		}
		accepted += n
		data = data[n:]
	}
	return accepted, nil
}
func encodeWorkerArgs(args []string) ([]byte, error) {
	total := 4
	for _, arg := range args {
		if len(arg) > workerArgsBytes-4 || total > workerArgsBytes-4-len(arg) {
			return nil, errors.New("worker arguments exceed 1 MiB")
		}
		total += 4 + len(arg)
	}
	data := make([]byte, 0, total)
	data = append32(data, uint32(len(args)))
	for _, arg := range args {
		data = append32(data, uint32(len(arg)))
		data = append(data, arg...)
	}
	return data, nil
}
func decodeWorkerArgs(data []byte) ([]string, error) {
	if len(data) < 4 {
		return nil, errors.New("invalid worker arguments")
	}
	count := u32(data)
	data = data[4:]
	if count > uint32(len(data)/4) {
		return nil, errors.New("invalid worker argument count")
	}
	args := make([]string, 0, int(count))
	for range count {
		if len(data) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		n := binary.LittleEndian.Uint32(data)
		data = data[4:]
		if uint64(n) > uint64(len(data)) {
			return nil, io.ErrUnexpectedEOF
		}
		args = append(args, string(data[:n]))
		data = data[n:]
	}
	if len(data) != 0 {
		return nil, errors.New("invalid worker arguments")
	}
	return args, nil
}

// Resolve fixed host imports before authorizing execution. This does not
// instantiate the guest or execute a WASM start function during compilation.
func workerImportsAvailable(rt wazero.Runtime, compiled wazero.CompiledModule) bool {
	if len(compiled.ImportedMemories()) != 0 {
		return false
	}
	for _, definition := range compiled.ImportedFunctions() {
		module, name, _ := definition.Import()
		host := rt.Module(module)
		if host == nil {
			return false
		}
		fn := host.ExportedFunctionDefinitions()[name]
		if fn == nil {
			return false
		}
		if !slices.Equal(fn.ParamTypes(), definition.ParamTypes()) || !slices.Equal(fn.ResultTypes(), definition.ResultTypes()) {
			return false
		}
	}
	return true
}
