package executor

import (
	"context"
	"debuglet/internal/executor/transport"

	"go.uber.org/zap"
)

func (e *Executor) OnStart(ctx context.Context, spec transport.Upload) error {
	return nil
}

func (e *Executor) OnError(debugletID string, err error) {
	e.logger.Error("Debuglet failed", zap.String("debugletID", debugletID), zap.Error(err))
}
