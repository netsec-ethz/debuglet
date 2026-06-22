package executor

import (
	"context"
	"debuglet/internal/executor/transport/rpc"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

func (e *Executor) HandleUpload(ctx context.Context, upload rpc.Spec) {
	// TODO: perform checks and throw error if can't submit

	e.logger.Debug("Handling upload", zap.String("debugletID", upload.DebugletID))
	if err := e.scheduler.Insert(upload); err != nil {
		e.logger.Error("Failed to schedule debuglet spec", zap.Error(err))
		err = fmt.Errorf("failed to schedule: %w", err)
		if err2 := e.control.SendError(ctx, &upload.DebugletID, err); err2 != nil {
			e.logger.Error("Failed to forward error to dispatcher", zap.Error(err2), zap.NamedError("original", err))
		}
	}
}

func (e *Executor) HandleAbort(ctx context.Context, debugletID, reason string) {
	e.logger.Debug("Handling abort", zap.String("debugletID", debugletID), zap.String("reason", reason))
	existed := e.scheduler.Remove(debugletID)
	if existed {
		e.logger.Info("Removed debuglet from storage before it was started", zap.String("debugletID", debugletID))
		return
	}

	e.mu.Lock()
	run, exists := e.running[debugletID]
	e.mu.Unlock()
	if !exists {
		e.logger.Error("Did not find debuglet when aborting. Probably due to a race condition between OnStart and Abort being called at the same time", zap.String("debugletID", debugletID))
		return
	}
	run.cancelCtx(errors.New(reason))
}

func (e *Executor) HandleUpdate(ctx context.Context, updates []rpc.Update) {
	e.logger.Debug("Handling update", zap.Objects("destination", updates))
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, up := range updates {
		e.limiter.SetAddrCapacity(up.Address, up.Limit)
	}
}
