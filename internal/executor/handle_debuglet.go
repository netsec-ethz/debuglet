package executor

import (
	"context"
	"debuglet/internal/executor/debuglet"
	"debuglet/internal/executor/transport/rpc"
	"debuglet/protocol"
	"errors"
	"time"

	"go.uber.org/zap"
)

func (e *Executor) OnStart(ctx context.Context, spec rpc.Spec) {
	ctx, cancel := context.WithCancelCause(ctx)

	client := rpc.NewDebugletClient(e.logger, *e.control.GRPCClient(), spec, e.cfg.ExecutorID)
	e.running[spec.DebugletID] = client

	go func() {
		if err := client.Listen(ctx); err != nil {
			cancel(err)
			// TODO: failed debuglets are still stored in e.running. Makes sense to move/store elsewhere
		}
	}()

	select {
	case <-ctx.Done():
		e.logger.Error("Failed to setup debuglet GRPC session", zap.String("debugletID", spec.DebugletID), zap.Error(context.Cause(ctx)))
		return
	case <-client.Ready():
	}

	// ======== INITIALIZE ========
	client.SendSetState(protocol.RunState_RUN_STATE_INITIALIZING)
	deb := debuglet.New(e.logger, spec.DebugletID, e.teslaSchedule)

	subCtx, cancelInit := context.WithTimeout(ctx, time.Second)
	err := deb.Init(subCtx, spec.Wasm, spec.Policy.Addresses)
	cancelInit()
	if err != nil {
		deb.Close()
		var zapError zap.Field
		if ctx.Err() == nil {
			zapError = zap.Error(err)
		} else {
			zapError = zap.Error(context.Cause(ctx))
		}
		cancel(err)
		e.logger.Error("Failed to initialize debuglet", zap.String("debugletID", spec.DebugletID), zapError)
		return
	}

	// ======== RUN/START ========
	if err := client.SendSetState(protocol.RunState_RUN_STATE_STARTED); err != nil {
		e.logger.Error("Failed to set state to 'started'", zap.String("debugletID", spec.DebugletID), zap.Error(err))
	}

	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		for output := range deb.OutputChan() {
			client.SendOutput(output)
		}
	}()

	subCtx, cancelRun := context.WithTimeout(ctx, spec.Policy.Timeout)
	err = deb.Run(subCtx)
	cancelRun()
	deb.Close()

	// TODO: determine how to differentiate between wasm code errors and errors when trying to start up a debuglet
	if err != nil {
		var zapError zap.Field
		if ctx.Err() == nil {
			zapError = zap.Error(err)
		} else {
			zapError = zap.Error(context.Cause(ctx))
		}
		cancel(err)
		e.logger.Error("Failed to run debuglet", zap.String("debugletID", spec.DebugletID), zapError)
		return
	}

	// ======== CLEANUP ========
	<-outputDone
	client.SendExit(0, nil)

	// Close the debuglet grpc stream
	cancel(errors.New("debuglet finished"))

	// TODO: proper mutex for deleting/adding debuglet spec while handling aborts
	delete(e.running, spec.DebugletID)
}
