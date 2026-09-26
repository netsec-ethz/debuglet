// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type RunningDebuglet struct {
	id        uuid.UUID
	operation *debugletOperation
}

func (e *Executor) OnDebugletFailed(ctx context.Context, spec scheduler.Spec, err error) scheduler.Completion {
	if errors.Is(err, scheduler.ErrDebugletAlreadyStarted) {
		e.logger.Warn("Debuglet already started, ignoring", zap.String("debugletID", spec.DebugletID.String()))
		// TODO: refund debuglet
	}
	op := newDebugletOperation(ctx)
	defer op.cancel(nil)
	completion := op.finish(err, nil)
	e.reportDebugletExit(op, spec)
	return completion
}

func (e *Executor) OnDebugletStart(ctx context.Context, spec scheduler.Spec) scheduler.Completion {
	// Scheduler cancellation already reaches this callback. Its nested operation
	// exists before any outbound allocation or resource initialization.
	op := newDebugletOperation(ctx)
	defer op.cancel(nil)
	pump, err := e.debugletHandler(op, spec)
	completion := op.finish(err, pump)
	e.unregisterDebuglet(spec.DebugletID, op)
	e.reportDebugletExit(op, spec)
	return completion
}

func (e *Executor) debugletHandler(op *debugletOperation, spec scheduler.Spec) (*outputPump, error) {
	ctx := op.ctx
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if err := e.allocateDebuglet(ctx, spec); err != nil {
		return nil, fmt.Errorf("failed to allocate debuglet: %w", err)
	}
	if err := e.checkExecutionLease(ctx, spec.Binding); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	deb, err := e.registerDebuglet(spec, op)
	if err != nil {
		return nil, fmt.Errorf("failed to register debuglet: %w", err)
	}
	if err := e.initializeDebuglet(ctx, spec, deb); err != nil {
		return nil, fmt.Errorf("failed to initialize debuglet: %w", err)
	}
	pump, err := e.propagateOutputToStream(op, spec.DebugletID, spec.Binding)
	if err != nil {
		return pump, fmt.Errorf("failed to open stream for debuglet output: %w", err)
	}
	timedCtx, cancel := context.WithTimeoutCause(ctx, spec.Policy.Timeout, policyTimeout{budget: spec.Policy.Timeout})
	defer cancel()
	// Forward the execution deadline into the same resource closer. Stop joins
	// this forwarding callback when natural completion wins the race.
	deadlineJoined := make(chan struct{})
	stopDeadline := context.AfterFunc(timedCtx, func() { op.cancel(context.Cause(timedCtx)); close(deadlineJoined) })
	defer func() {
		if !stopDeadline() {
			<-deadlineJoined
		}
	}()
	if err := e.runDebuglet(timedCtx, spec, deb, pump.Input); err != nil {
		return pump, fmt.Errorf("failed to run debuglet: %w", err)
	}
	return pump, nil
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
	client, err := e.dispatcherClient(ctx, spec.Binding)
	if err != nil {
		return err
	}
	resp, err := client.DebugletAllocate(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to allocate on dispatcher: %w", err)
	}
	if err := e.checkExecutionLease(ctx, spec.Binding); err != nil {
		return err
	}

	up := &pb.BandwidthRequest{Limits: resp.GetAllocatedLimits()}
	_, err = e.applyBandwidth(spec.Binding, up)
	if err != nil {
		return fmt.Errorf("failed to set bandwidth limits: %w", err)
	}

	return err
}

func (e *Executor) registerDebuglet(spec scheduler.Spec, op *debugletOperation) (runtimeDebuglet, error) {
	e.mu.Lock()
	if len(e.running) >= e.cfg.Resources.MaxDebuglets {
		e.mu.Unlock()
		return nil, fmt.Errorf("max debuglet capacity reached (id=%s)", spec.DebugletID)
	}
	if _, exists := e.running[spec.DebugletID]; exists {
		e.mu.Unlock()
		return nil, fmt.Errorf("debuglet already registered (id=%s)", spec.DebugletID)
	}
	e.running[spec.DebugletID] = RunningDebuglet{id: spec.DebugletID, operation: op}
	e.mu.Unlock()
	var deb runtimeDebuglet
	if e.newRuntime != nil {
		deb = e.newRuntime(spec)
	} else {
		operator, policyErr := e.cfg.Network.Policy.Compile()
		if policyErr != nil {
			return nil, fmt.Errorf("invalid operator network policy: %w", policyErr)
		}
		deb = debuglet.New(e.logger, spec.DebugletID, spec.TransactionID, spec.Policy, operator,
			e.teslaSchedule, e.limiter, e.packetCount, e.iface, e.portManager)
	}
	if deb == nil {
		return nil, errors.New("debuglet runtime factory returned nil")
	}
	// Finish local registration before cancellation may remove its limiter
	// entry. Every partial registration then closes through the same runtime.
	defer op.ownRuntime(deb)
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
	// A new competitor moves the shares of every run that is already active.
	e.publishLimits(spec.Policy.Addresses)

	return deb, nil
}

func (e *Executor) unregisterDebuglet(id uuid.UUID, op *debugletOperation) {
	e.mu.Lock()
	if running, ok := e.running[id]; ok && running.operation == op {
		delete(e.running, id)
		// Registration set this run's executor-wide limit. Removing it under
		// e.mu, after the run left e.running, means no concurrent publish can
		// set it again, so the counter's map never keeps a departed run.
		if err := e.packetCount.DeleteExecLimit(id); err != nil {
			e.logger.Warn("Failed to remove executor limit", zap.String("debugletID", id.String()), zap.Error(err))
		}
	}
	// A departure releases its share to whatever is still running.
	e.publishLimitsLocked(nil)
	e.mu.Unlock()
	// Runtime Close owns limiter/tagger/port release exactly once.
}

func (e *Executor) initializeDebuglet(ctx context.Context, spec scheduler.Spec, deb runtimeDebuglet) error {
	client, err := e.dispatcherClient(ctx, spec.Binding)
	if err != nil {
		return err
	}
	_, err = client.DebugletState(ctx, &pb.DebugletStateRequest{
		DebugletId: spec.DebugletID.String(),
		ExecutorId: e.cfg.Identity.ExecutorID,
		State:      pb.RunState_RUN_STATE_INITIALIZING,
	})
	if err != nil {
		return fmt.Errorf("failed to set state to 'initializing': %w", err)
	}
	if err := e.checkExecutionLease(ctx, spec.Binding); err != nil {
		return err
	}
	err = deb.InitRuntime(ctx, spec.Wasm)
	if err != nil {
		return fmt.Errorf("failed to initialize debuglet runtime: %w", err)
	}
	if err := e.checkExecutionLease(ctx, spec.Binding); err != nil {
		return err
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

func (e *Executor) runDebuglet(ctx context.Context, spec scheduler.Spec, deb runtimeDebuglet, outputCh chan<- []byte) error {
	client, err := e.dispatcherClient(ctx, spec.Binding)
	if err != nil {
		return err
	}
	_, err = client.DebugletState(ctx, &pb.DebugletStateRequest{
		DebugletId: spec.DebugletID.String(),
		ExecutorId: e.cfg.Identity.ExecutorID,
		State:      pb.RunState_RUN_STATE_STARTED,
	})
	if err != nil {
		return fmt.Errorf("failed to set state to 'started': %w", err)
	}
	if err := e.checkExecutionLease(ctx, spec.Binding); err != nil {
		return err
	}

	return deb.Run(ctx, outputCh, spec.Args)
}
