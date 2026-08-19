package executor

import (
	"context"
	"debuglet/internal/executor/debuglet"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/scheduler"
	pb "debuglet/protocol"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type RunningDebuglet struct {
	id        uuid.UUID
	cancelCtx func(error)
	debuglet  *debuglet.Debuglet
}

func (e *Executor) OnDebugletFailed(ctx context.Context, spec scheduler.Spec, err error) {
	if errors.Is(err, scheduler.ErrDebugletAlreadyStarted) {
		e.logger.Warn("Debuglet already started, ignoring", zap.String("debugletID", spec.DebugletID.String()))
		// TODO: refund debuglet
	}
}

func (e *Executor) OnDebugletStart(ctx context.Context, spec scheduler.Spec) {
	if err := e.debugletHandler(ctx, spec); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("debuglet handler failed due to context error: %w", ctx.Err())
		}
		e.logger.Error("Debuglet handler failed", zap.String("debugletID", spec.DebugletID.String()), zap.Error(err))
		errMsg := err.Error()

		if _, err := e.Bidi.Client.DebugletExit(ctx, &pb.DebugletExitRequest{
			DebugletId:   spec.DebugletID.String(),
			ExitCode:     -1,
			ErrorMessage: &errMsg,
		}); err != nil {
			e.logger.Error("Failed to notify debuglet exit", zap.String("debugletID", spec.DebugletID.String()), zap.Error(err))
		}
	}
}

func (e *Executor) debugletHandler(ctx context.Context, spec scheduler.Spec) error {
	// TODO: remove allocate step
	if err := e.allocateDebuglet(ctx, spec); err != nil {
		return fmt.Errorf("failed to allocate debuglet: %w", err)
	}

	ctx, cancelDebuglet := context.WithCancelCause(ctx)
	deb, err := e.registerDebuglet(spec, cancelDebuglet)
	defer e.unregisterDebuglet(ctx, spec)
	if err != nil {
		return fmt.Errorf("failed to register debuglet: %w", err)
	}
	defer cancelDebuglet(nil)

	// ======== INITIALIZE ========
	if err := e.initializeDebuglet(ctx, spec, deb); err != nil {
		return fmt.Errorf("failed to initialize debuglet: %w", err)
	}

	// ======== RUN/START ========
	outputCh, err := e.propagateOutputToStream(ctx, spec.DebugletID)
	if err != nil {
		return fmt.Errorf("failed to open stream for debuglet output: %w", err)
	}

	naturalExit := atomic.Bool{}
	timedCtx, cancel := context.WithTimeoutCause(ctx, spec.Policy.Timeout, fmt.Errorf("timeout of %s exceeded", spec.Policy.Timeout))
	defer cancel()
	go func() {
		<-timedCtx.Done()
		if !naturalExit.Load() {
			e.logger.Warn("Debuglet context done, closing debuglet", zap.String("debugletID", spec.DebugletID.String()), zap.Error(timedCtx.Err()))
			// Forces debuglet to close all it's resources. It could be stuck in a conn.Read() call in a host function, which does not
			// respect contexts closing nor can't be closed by wazero.
			deb.Close(timedCtx)
		}
	}()
	if err := e.runDebuglet(timedCtx, spec, deb, outputCh); err != nil {
		return fmt.Errorf("failed to run debuglet: %w", err)
	}
	naturalExit.Store(true)

	e.Bidi.Client.DebugletExit(ctx, &pb.DebugletExitRequest{
		DebugletId: spec.DebugletID.String(),
		ExitCode:   0,
	})

	return nil
}

func (e *Executor) allocateDebuglet(ctx context.Context, spec scheduler.Spec) error {
	req := &pb.DebugletAllocateRequest{
		DebugletId:    spec.DebugletID.String(),
		ExecutorId:    e.cfg.Identity.ExecutorID,
		TransactionId: spec.TransactionID,
		Policy: &pb.DebugletPolicy{
			FloorBw:   spec.Policy.FloorBW,
			CeilBw:    spec.Policy.CeilBW,
			TimeoutMs: spec.Policy.Timeout.Milliseconds(),
			Addresses: spec.Policy.Addresses,
		},
	}
	resp, err := e.Bidi.Client.DebugletAllocate(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to allocate on dispatcher: %w", err)
	}

	up := &pb.BandwidthRequest{Limits: resp.GetAllocatedLimits()}
	_, err = e.OnBandwidth(ctx, up)
	if err != nil {
		return fmt.Errorf("failed to set bandwidth limits: %w", err)
	}

	return err
}

func (e *Executor) registerDebuglet(spec scheduler.Spec, cancelFunc context.CancelCauseFunc) (*debuglet.Debuglet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.running) >= e.cfg.Resources.MaxDebuglets {
		err := fmt.Errorf("max debuglet capacity reached (id=%s)", spec.DebugletID)
		return nil, err
	}

	deb := debuglet.New(e.logger,
		spec.DebugletID,
		spec.TransactionID,
		spec.Policy,
		e.teslaSchedule,
		e.limiter,
		e.packetCount,
		e.iface,
		e.portManager,
	)

	e.running[spec.DebugletID] = RunningDebuglet{
		id:        spec.DebugletID,
		cancelCtx: cancelFunc,
		debuglet:  deb,
	}

	err := e.limiter.InsertDebuglet(spec.DebugletID, app.Bitrate(spec.Policy.FloorBW), app.Bitrate(spec.Policy.CeilBW), spec.Policy.Addresses)
	if err != nil {
		return nil, err
	}
	execLimit, _, err := e.limiter.GetExecLimit(spec.DebugletID)
	if err != nil {
		return nil, err
	}
	if err = e.packetCount.SetExecLimit(spec.DebugletID, execLimit); err != nil {
		return nil, err
	}

	return deb, nil
}

func (e *Executor) unregisterDebuglet(ctx context.Context, spec scheduler.Spec) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if running, ok := e.running[spec.DebugletID]; ok {
		running.debuglet.Close(ctx)
		running.cancelCtx(nil)
		delete(e.running, spec.DebugletID)
	}
	e.limiter.RemoveDebuglet(spec.DebugletID)
}

func (e *Executor) initializeDebuglet(ctx context.Context, spec scheduler.Spec, deb *debuglet.Debuglet) error {
	_, err := e.Bidi.Client.DebugletState(ctx, &pb.DebugletStateRequest{
		DebugletId: spec.DebugletID.String(),
		ExecutorId: e.cfg.Identity.ExecutorID,
		State:      pb.RunState_RUN_STATE_INITIALIZING,
	})
	if err != nil {
		return fmt.Errorf("failed to set state to 'initializing': %w", err)
	}
	err = deb.InitRuntime(ctx, spec.Wasm)
	if err != nil {
		return fmt.Errorf("failed to initialize debuglet runtime: %w", err)
	}

	subCtx, cancelInit := context.WithTimeout(ctx, 10*time.Second)
	defer cancelInit()
	req := debuglet.StartServersReq{
		TCP:   spec.Policy.ListenTCP,
		UDP:   spec.Policy.ListenUDP,
		SCION: spec.Policy.ListenSCION,
	}
	if err := deb.StartServers(subCtx, req); err != nil {
		if spec.Policy.ListenTCP || spec.Policy.ListenUDP {
			return fmt.Errorf("failed to start listener: %w", err)
		}
		e.logger.Warn("Failed to startup servers for debuglet. Ignoring", zap.String("debugletID", spec.DebugletID.String()), zap.Error(err))
	}
	return nil
}

func (e *Executor) propagateOutputToStream(ctx context.Context, id uuid.UUID) (chan<- []byte, error) {
	stream, err := e.Bidi.Client.DebugletStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open debuglet stream: %w", err)
	}
	err = stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Ident{Ident: &pb.DebugletIdent{DebugletId: id.String(), ExecutorId: e.cfg.Identity.ExecutorID}}})
	if err != nil {
		return nil, fmt.Errorf("failed to send debuglet ident: %w", err)
	}
	outputCh := make(chan []byte, 1024)
	go func() {
		for out := range outputCh {
			err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: &pb.DebugletOutput{Output: out, Timestamp: timestamppb.Now()}}})
			if err != nil {
				e.logger.Error("Failed to send debuglet output", zap.String("debugletID", id.String()), zap.Error(err))
				return
			}
		}
	}()
	return outputCh, nil
}

func (e *Executor) runDebuglet(ctx context.Context, spec scheduler.Spec, deb *debuglet.Debuglet, outputCh chan<- []byte) error {
	_, err := e.Bidi.Client.DebugletState(ctx, &pb.DebugletStateRequest{
		DebugletId: spec.DebugletID.String(),
		ExecutorId: e.cfg.Identity.ExecutorID,
		State:      pb.RunState_RUN_STATE_STARTED,
	})
	if err != nil {
		return fmt.Errorf("failed to set state to 'started': %w", err)
	}

	return deb.Run(ctx, outputCh, spec.Args)
}
