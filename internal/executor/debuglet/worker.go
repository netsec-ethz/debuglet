// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
	"github.com/tetratelabs/wazero/sys"
)

// Worker preserves the parent's networking environment. Only WASM compilation,
// WASI and linear memory live in the supervised process.
type Worker struct {
	*Debuglet
	supervisor                         *isolation.Supervisor
	mu                                 sync.Mutex
	initialized, closed, compiled, ran bool
	initDone                           chan struct{}
	cancel                             context.CancelCauseFunc
	runCancel                          context.CancelCauseFunc
	conn                               net.Conn
	process                            *isolation.Process
	closeOnce                          sync.Once
	closeErr                           error
	functions                          []wasm.Function
}

func NewWorker(parent *Debuglet, supervisor *isolation.Supervisor) *Worker {
	return &Worker{Debuglet: parent, supervisor: supervisor, initDone: make(chan struct{}), functions: wasm.Functions(parent.env)}
}

func (w *Worker) InitRuntime(ctx context.Context, module []byte) error {
	w.mu.Lock()
	if w.closed || w.initialized {
		w.mu.Unlock()
		return net.ErrClosed
	}
	w.initialized = true
	lifetime, cancel := context.WithCancelCause(ctx)
	w.cancel = cancel
	w.mu.Unlock()
	phase, end := context.WithTimeoutCause(lifetime, time.Duration(w.supervisor.Config().CompileWallMS)*time.Millisecond, isolation.ErrCompileBudget)
	defer end()
	joined := make(chan struct{})
	stop := context.AfterFunc(phase, func() { _ = w.Close(context.Background()); close(joined) })
	err := w.compile(phase, module)
	// Close may be waiting for a child whose Start was in progress. Compilation
	// must publish its completion before joining that closer.
	close(w.initDone)
	if !stop() {
		<-joined
	}
	if phase.Err() != nil {
		err = errors.Join(context.Cause(phase), err)
	}
	if err != nil {
		err = errors.Join(err, w.Close(context.Background()))
		if w.process != nil && w.process.BudgetExceeded() {
			err = errors.Join(isolation.ErrCompileBudget, err)
		}
	}
	return err
}

func (w *Worker) compile(ctx context.Context, module []byte) error {
	if len(module) > workerModuleBytes {
		return &CompileError{Err: errors.New("module exceeds 24 MiB")}
	}
	parent, child, err := workerPair()
	if err != nil {
		return err
	}
	defer child.Close()
	conn, err := net.FileConn(parent)
	_ = parent.Close()
	if err != nil {
		return err
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	w.conn = conn
	w.mu.Unlock()
	process, err := w.supervisor.Start(ctx, child, workerArgument)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.process = process
	closed := w.closed
	w.mu.Unlock()
	if closed || ctx.Err() != nil {
		return errors.Join(context.Cause(ctx), net.ErrClosed, process.Close())
	}
	b := bridge{conn}
	request := append32(append32(nil, uint32(len(module))), w.supervisor.Config().MemoryPages)
	if err = b.send(frameInit, request); err != nil {
		return isolation.ErrCompileWorker
	}
	if err = b.blob(module); err != nil {
		return isolation.ErrCompileWorker
	}
	kind, data, err := b.read()
	if err != nil {
		return isolation.ErrCompileWorker
	}
	if kind != frameCompiled || len(data) != 1 {
		return isolation.ErrCompileWorker
	}
	if data[0] != 0 {
		return &CompileError{Err: errors.New("module rejected by compiler")}
	}
	w.mu.Lock()
	if w.closed || ctx.Err() != nil {
		w.mu.Unlock()
		return errors.Join(net.ErrClosed, context.Cause(ctx))
	}
	w.compiled = true
	w.mu.Unlock()
	process.Compiled()
	return nil
}

func (w *Worker) Run(ctx context.Context, output chan<- []byte, args []string) (result error) {
	defer close(output)
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(net.ErrClosed)
	w.mu.Lock()
	if w.closed || !w.compiled || w.ran {
		w.mu.Unlock()
		return net.ErrClosed
	}
	w.ran = true
	w.runCancel = cancel
	process, conn := w.process, w.conn
	w.mu.Unlock()
	defer func() {
		result = errors.Join(result, w.Close(context.Background()))
		if process.BudgetExceeded() {
			result = errors.Join(isolation.ErrExecutionBudget, result)
		}
	}()
	phase, end := context.WithTimeoutCause(runCtx, time.Duration(w.supervisor.Config().RunWallMS)*time.Millisecond, isolation.ErrExecutionBudget)
	defer end()
	joined := make(chan struct{})
	stop := context.AfterFunc(phase, func() { _ = w.Close(context.Background()); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	if err := phase.Err(); err != nil {
		return context.Cause(phase)
	}
	if err := process.RunLimits(); err != nil {
		return err
	}
	data, err := encodeWorkerArgs(args)
	if err != nil {
		return err
	}
	b := bridge{conn}
	if err = b.send(frameRun, append32(nil, uint32(len(data)))); err != nil {
		return isolation.ErrWorker
	}
	if err = b.blob(data); err != nil {
		return isolation.ErrWorker
	}
	err = w.receive(phase, b, output)
	if phase.Err() != nil {
		return errors.Join(context.Cause(phase), err)
	}
	return err
}

func (w *Worker) receive(ctx context.Context, b bridge, output chan<- []byte) error {
	var hostErr error
	for {
		kind, data, err := b.read()
		if err != nil {
			return errors.Join(isolation.ErrWorker, hostErr)
		}
		switch kind {
		case frameOutput:
			if len(data) == 0 {
				return isolation.ErrWorker
			}
			select {
			case output <- data:
			case <-ctx.Done():
				return errors.Join(ErrOutputIncomplete, context.Cause(ctx))
			}
			if err = b.send(frameReturn, nil); err != nil {
				return isolation.ErrWorker
			}
		case frameCall:
			if len(data) < 4 {
				return isolation.ErrWorker
			}
			id := u32(data)
			if uint64(id) >= uint64(len(w.functions)) {
				return isolation.ErrWorker
			}
			f := w.functions[id]
			count := max(len(f.Params), len(f.Results))
			if len(data) != 4+8*count {
				return isolation.ErrWorker
			}
			stack := make([]uint64, count)
			for i := range stack {
				stack[i] = binary.LittleEndian.Uint64(data[4+8*i:])
			}
			if err = invokeHost(ctx, f, remoteMemory{b}, stack); err != nil {
				hostErr = err
				err = b.send(frameTrap, nil)
			} else {
				result := make([]byte, 8*count)
				for i, v := range stack {
					binary.LittleEndian.PutUint64(result[8*i:], v)
				}
				err = b.send(frameReturn, result)
			}
			if err != nil {
				return errors.Join(isolation.ErrWorker, hostErr)
			}
		case frameResult:
			if len(data) == 1 && data[0] == 0 {
				return hostErr
			}
			if len(data) == 5 && data[0] == 2 {
				return errors.Join(sys.NewExitError(u32(data[1:])), hostErr)
			}
			if len(data) == 1 && data[0] == 1 {
				return errors.Join(isolation.ErrWorker, hostErr)
			}
			return isolation.ErrWorker
		default:
			return isolation.ErrWorker
		}
	}
}

func (w *Worker) Close(ctx context.Context) error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		cancel, runCancel, conn, process, started := w.cancel, w.runCancel, w.conn, w.process, w.initialized
		w.mu.Unlock()
		if cancel != nil {
			cancel(net.ErrClosed)
		}
		if runCancel != nil {
			runCancel(net.ErrClosed)
		}
		if conn != nil {
			_ = conn.Close()
		}
		if process != nil {
			w.closeErr = process.Close()
		}
		// A child which was between admission and publication must be reaped too.
		if started {
			<-w.initDone
		}
		w.mu.Lock()
		late := w.process
		w.mu.Unlock()
		if late != nil && late != process {
			w.closeErr = errors.Join(w.closeErr, late.Close())
		}
	})
	// Host calls may finish after the first closer. Re-observe the parent's
	// late cleanup errors after those producers join, as the local engine does.
	return errors.Join(w.closeErr, w.Debuglet.Close(ctx))
}
