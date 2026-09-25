package executor

import (
	"context"
	"errors"
	"sync"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

// runtimeDebuglet is the executor's nested resource owner. The scheduler owns
// admission and the outer completion, including persistent finalization.
type runtimeDebuglet interface {
	InitRuntime(context.Context, []byte) error
	StartServers(context.Context, debuglet.StartServersReq) error
	Run(context.Context, chan<- []byte, []string) error
	Close(context.Context) error
}

type debugletOperation struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	closeRequest chan struct{}
	closeOnce    sync.Once
	watcherDone  chan struct{}
	closeErr     error // initial result published by watcherDone
	runtime      runtimeDebuglet
	resourceDone chan struct{}
	outcome      error // selected once and published by resourceDone
}

func newDebugletOperation(parent context.Context) *debugletOperation {
	ctx, cancel := context.WithCancelCause(parent)
	return &debugletOperation{ctx: ctx, cancel: cancel, closeRequest: make(chan struct{}), resourceDone: make(chan struct{})}
}

func (op *debugletOperation) ownRuntime(runtime runtimeDebuglet) {
	op.runtime = runtime
	op.watcherDone = make(chan struct{})
	go func() {
		defer close(op.watcherDone)
		select {
		case <-op.ctx.Done():
		case <-op.closeRequest:
		}
		// Closing breaks I/O. It must not wait for Run or scheduler completion.
		// A runtime which ignores this deadline keeps this watcher and its outer
		// callback owned; Cancel/Shutdown may time out without claiming quiescence.
		ctx, end := context.WithTimeout(context.WithoutCancel(op.ctx), scheduler.CleanupTimeout)
		defer end()
		op.closeErr = runtime.Close(ctx)
	}()
}

// finish is called only after setup/Run has returned. It retains ownership
// until every resource worker actually returns, even after a bounded wait fails.
func (op *debugletOperation) finish(workErr error, pump *outputPump) scheduler.Completion {
	if workErr != nil {
		op.cancel(workErr)
	}
	op.closeOnce.Do(func() { close(op.closeRequest) })
	if pump != nil {
		if op.ctx.Err() != nil {
			pump.Cancel()
		}
		ctx, end := context.WithTimeout(context.WithoutCancel(op.ctx), scheduler.CleanupTimeout)
		err := pump.Wait(ctx)
		end()
		if err != nil {
			op.cancel(err)
			pump.Cancel()
			// Wait synchronously: an unresponsive transport must not leave an
			// abandoned waiter or manufacture callback completion.
			workErr = errors.Join(workErr, err, pump.Wait(context.Background()))
		}
	}
	if op.watcherDone != nil {
		<-op.watcherDone
		// Setup/Run may have disposed of resources published after the initial
		// close snapshot. Reobserve the idempotent aggregate only after their
		// callers and the close watcher have joined; no resource closes twice.
		ctx, end := context.WithTimeout(context.WithoutCancel(op.ctx), scheduler.CleanupTimeout)
		op.closeErr = op.runtime.Close(ctx)
		end()
	}
	if cause := context.Cause(op.ctx); cause != nil {
		op.outcome = cause
	} else {
		op.outcome = workErr
	}
	close(op.resourceDone)
	return scheduler.Completion{CleanupErr: op.closeErr}
}
