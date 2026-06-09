package executor

import (
	"debuglet/internal/executor/transport/rpc"
	"fmt"

	"go.uber.org/zap"
)

func (e *Executor) HandleUpload(upload rpc.Upload) {
	if err := e.storage.Insert(upload); err != nil {
		e.logger.Error("Failed to insert debuglet spec", zap.Error(err))
		err = fmt.Errorf("failed to insert: %w", err)
		if err2 := e.control.SendError(&upload.DebugletID, err); err2 != nil {
			e.logger.Error("Failed to forward error to dispatcher", zap.Error(err2), zap.NamedError("original", err))
		}
	}
}

func (e *Executor) HandleAbort(debugletID, reason string) {
	e.logger.Debug("Handling abort", zap.String("debugletID", debugletID), zap.String("reason", reason))
	existed := e.storage.Remove(debugletID)
	if existed {
		e.logger.Info("Removed debuglet from storage before it was started", zap.String("debugletID", debugletID))
		return
	}

	// TODO: try to abort debuglet if it's still being executed, since at this point either:
	// - OnStart has already been called
	// - this is an unknown debugletID
	// - (it's a race condition right after the debuglet has been removed from storage, but OnStart hasn't been called properly yet)
}
