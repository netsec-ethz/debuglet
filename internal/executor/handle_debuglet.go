package executor

import (
	"context"
	"debuglet/internal/executor/debuglet"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/transport/rpc"
	"debuglet/protocol"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type RunningDebuglet struct {
	id        uuid.UUID
	addresses []string
	client    *rpc.DebugletClient
	cancelCtx func(error)
	debuglet  *debuglet.Debuglet
}

func (e *Executor) OnStart(ctx context.Context, spec rpc.Spec, preRunLock chan<- struct{}) {
	debUUID, err := uuid.Parse(spec.DebugletID)
	if err != nil {
		e.logger.Error("Invalid debuglet UUID", zap.String("debugletID", spec.DebugletID), zap.Error(err))
		close(preRunLock)
		return
	}

	ctx, cancel := context.WithCancelCause(ctx)

	client := rpc.NewDebugletClient(e.logger, *e.control.GRPCClient(), spec, e.cfg.ExecutorID)
	e.mu.Lock()

	if len(e.running) >= e.cfg.MaxDebuglets {
		err := fmt.Errorf("cannot add another debuglet (id=%s)", spec.DebugletID)
		if err2 := e.control.SendError(ctx, &spec.DebugletID, err); err2 != nil {
			e.logger.Error("Failed to forward error to dispatcher", zap.Error(err2), zap.NamedError("original", err))
		}
		close(preRunLock)
		cancel(nil)
		e.mu.Unlock()
		return
	}

	e.running[spec.DebugletID] = RunningDebuglet{
		id:        debUUID,
		addresses: spec.Policy.Addresses,
		client:    client,
		cancelCtx: cancel,
	}

	if err = e.limiter.InsertDebuglet(debUUID.String(), app.Bitrate(spec.Policy.FloorBW), app.Bitrate(spec.Policy.CeilBW), spec.Policy.Addresses); err != nil {
		e.logger.Error("Failed to insert debuglet into limiter", zap.String("debugletID", spec.DebugletID), zap.Error(err))
		close(preRunLock)
		e.mu.Unlock()
		return
	}
	execLimit, _, err := e.limiter.GetExecLimit(spec.DebugletID)
	if err != nil {
		e.logger.Error("Failed to get executor limit for debuglet", zap.String("debugletID", spec.DebugletID), zap.Error(err))
		close(preRunLock)
		e.mu.Unlock()
		return
	}
	if err = e.packetCount.SetExecLimit(debUUID, execLimit); err != nil {
		e.logger.Error("Failed to set executor limit for debuglet in eBPF packet count", zap.String("debugletID", spec.DebugletID), zap.Error(err))
		close(preRunLock)
		e.mu.Unlock()
		return
	}

	close(preRunLock)
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		delete(e.running, spec.DebugletID)
	}()

	listenDone := make(chan struct{})
	go func() {
		defer close(listenDone)
		if err := client.Listen(ctx); err != nil {
			cancel(err)
		}
	}()

	defer func() {
		cancel(nil)
		<-listenDone
	}()

	select {
	case <-ctx.Done():
		e.logger.Error("Failed to setup debuglet GRPC session", zap.String("debugletID", spec.DebugletID), zap.Error(context.Cause(ctx)))
		return
	case <-client.Ready():
	}

	// ======== INITIALIZE ========
	if err = client.SendSetState(protocol.RunState_RUN_STATE_INITIALIZING); err != nil {
		e.logger.Error("Failed to set state to 'initialized'", zap.String("debugletID", spec.DebugletID), zap.Error(err))
		client.SendExit(-1, err)
		return
	}

	deb := debuglet.New(e.logger, spec.DebugletID, spec.Policy, e.teslaSchedule, e.limiter, e.packetCount)
	e.mu.Lock()
	if running, ok := e.running[spec.DebugletID]; ok {
		running.debuglet = deb
		e.running[spec.DebugletID] = running
	}
	e.mu.Unlock()
	defer deb.Close(ctx)
	err = deb.InitRuntime(ctx, spec.Wasm)
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
		return deb.Run(subCtx, outputCh, spec.Args)
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
