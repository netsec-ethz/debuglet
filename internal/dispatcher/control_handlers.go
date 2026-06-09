package dispatcher

import (
	"context"

	"go.uber.org/zap"
)

type DispatcherControlHandler interface {
	HandleHello(ctx context.Context, h Hello) error
	HandleHeartbeat(ctx context.Context, hb Heartbeat) error
	HandleDisconnect(ctx context.Context, executorID string)
	HandleError(ctx context.Context, debugletID *string, err error)
}

func (d *Dispatcher) HandleHello(ctx context.Context, h Hello) error {
	d.RegisterExecutor(h.ExecutorID, h.SourceIP, h.TeslaDelay, h.TeslaAnchorTimestamp, h.TeslaAnchorKey)
	return nil
}
func (d *Dispatcher) HandleHeartbeat(ctx context.Context, hb Heartbeat) error {
	return nil
}
func (d *Dispatcher) HandleDisconnect(ctx context.Context, executorID string) {
	d.RemoveExecutor(executorID)
}
func (d *Dispatcher) HandleError(ctx context.Context, debugletID *string, err error) {
	d.logger.Error("Got executor error", zap.Stringp("debugletID", debugletID), zap.Error(err))
}
