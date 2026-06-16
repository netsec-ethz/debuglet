package executor

import (
	"context"
	"debuglet/internal/executor/debuglet"
	"debuglet/internal/executor/transport/rpc"
	"debuglet/protocol"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type RunningDebuglet struct {
	client    *rpc.DebugletClient
	cancelCtx func(error)
}

func (e *Executor) OnStart(ctx context.Context, spec rpc.Spec, preRunLock chan<- struct{}) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	client := rpc.NewDebugletClient(e.logger, *e.control.GRPCClient(), spec, e.cfg.ExecutorID)
	e.mu.Lock()

	if len(e.running) >= e.cfg.MaxDebuglets {
		err := fmt.Errorf("cannot add another debuglet (id=%s)", spec.DebugletID)
		if err2 := e.control.SendError(&spec.DebugletID, err); err2 != nil {
			e.logger.Error("Failed to forward error to dispatcher", zap.Error(err2), zap.NamedError("original", err))
		}
		close(preRunLock)
		e.mu.Unlock()
		return
	}

	e.running[spec.DebugletID] = RunningDebuglet{
		client:    client,
		cancelCtx: cancel,
	}
	close(preRunLock)
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		delete(e.running, spec.DebugletID)
	}()

	go func() {
		if err := client.Listen(ctx); err != nil {
			cancel(err)
		}
	}()

	select {
	case <-ctx.Done():
		e.logger.Error("Failed to setup debuglet GRPC session", zap.String("debugletID", spec.DebugletID), zap.Error(context.Cause(ctx)))
		return
	case <-client.Ready():
	}

	// ======== INITIALIZE ========
	if err := client.SendSetState(protocol.RunState_RUN_STATE_INITIALIZING); err != nil {
		e.logger.Error("Failed to set state to 'initialized'", zap.String("debugletID", spec.DebugletID), zap.Error(err))
		client.SendExit(-1, err)
		return
	}

	deb := debuglet.New(e.logger, spec.DebugletID, e.teslaSchedule)
	defer deb.Close(ctx)
	err := deb.InitRuntime(ctx, spec.Wasm, spec.Policy.Addresses)
	if err != nil {
		var zapError zap.Field
		if ctx.Err() == nil {
			zapError = zap.Error(err)
		} else {
			zapError = zap.Error(context.Cause(ctx))
		}
		e.logger.Error("Failed to initialize debuglet runtime", zap.String("debugletID", spec.DebugletID), zapError)
		client.SendExit(-1, err)
		return
	}

	subCtx, cancelInit := context.WithTimeout(ctx, time.Second)
	if err := deb.StartServers(subCtx); err != nil {
		e.logger.Warn("Failed to startup servers for debuglet. Ignoring", zap.String("debugletID", spec.DebugletID), zap.Error(err))
	}
	cancelInit()

	// ======== RUN/START ========
	if err := client.SendSetState(protocol.RunState_RUN_STATE_STARTED); err != nil {
		e.logger.Error("Failed to set state to 'started'", zap.String("debugletID", spec.DebugletID), zap.Error(err))
		client.SendExit(-1, err)
		return
	}

	outputCh := make(chan []byte, 1024)
	timedCtx, cancelRun := context.WithTimeout(ctx, spec.Policy.Timeout)
	g, subCtx := errgroup.WithContext(timedCtx)
	g.Go(func() error {
		return deb.Run(subCtx, outputCh)
	})

	for out := range outputCh {
		client.SendOutput(out)
	}

	cancelRun()

	if err := g.Wait(); err != nil {
		client.SendExit(-1, err)
	} else {
		client.SendExit(0, nil)
	}
}
