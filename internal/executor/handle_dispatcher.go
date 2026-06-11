package executor

import (
	"debuglet/internal/executor/transport/rpc"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

func (e *Executor) HandleUpload(upload rpc.Spec) {
	e.logger.Debug("Handling upload", zap.String("debugletID", upload.DebugletID))
	if err := e.scheduler.Insert(upload); err != nil {
		e.logger.Error("Failed to insert debuglet spec", zap.Error(err))
		err = fmt.Errorf("failed to insert: %w", err)
		if err2 := e.control.SendError(&upload.DebugletID, err); err2 != nil {
			e.logger.Error("Failed to forward error to dispatcher", zap.Error(err2), zap.NamedError("original", err))
		}
	}
}

func (e *Executor) HandleAbort(debugletID, reason string) {
	e.logger.Debug("Handling abort", zap.String("debugletID", debugletID), zap.String("reason", reason))
	existed := e.scheduler.Remove(debugletID)
	if existed {
		e.logger.Info("Removed debuglet from storage before it was started", zap.String("debugletID", debugletID))
		return
	}

	run, exists := e.running[debugletID]
	if !exists {
		e.logger.Error("Did not find debuglet when aborting. Probably due to a race condition between OnStart and Abort being called at the same time", zap.String("debugletID", debugletID))
		return
	}
	run.cancelCtx(errors.New(reason))
}
