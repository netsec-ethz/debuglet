package executor

import (
	"debuglet/internal/executor/transport"

	"go.uber.org/zap"
)

func (e *Executor) HandleUpload(upload transport.Upload) {
	if err := e.storage.Insert(upload); err != nil {
		e.logger.Error("Failed to insert debuglet spec", zap.Error(err))
		if err2 := e.control.SendError(&upload.DebugletID, err); err2 != nil {
			e.logger.Error("Failed to forward error to dispatcher", zap.Error(err2), zap.NamedError("original", err))
		}
	}
}
