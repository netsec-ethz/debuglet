package dispatcher

import (
	"context"

	"go.uber.org/zap"
)

type DispatcherControlHandler interface {
	HandleHello(ctx context.Context, h Hello) error
	HandleHeartbeat(ctx context.Context, hb Heartbeat) error
	HandleDisconnect(executorID string)
	HandleError(ctx context.Context, debugletID *string, err error)
	HandleResources(ctx context.Context, executorID string, capacity int64) error
}

func (d *Dispatcher) HandleHello(ctx context.Context, h Hello) error {
	d.RegisterExecutor(h.ExecutorID, h.SourceIP, h.TeslaDelay, h.TeslaAnchorTimestamp, h.TeslaAnchorKey)
	return nil
}

func (d *Dispatcher) HandleHeartbeat(ctx context.Context, hb Heartbeat) error {
	return d.keystore.Store(hb.ExecutorID, hb.TeslaKeyEpoch, hb.TeslaKey)
}

func (d *Dispatcher) HandleDisconnect(executorID string) {
	d.RemoveExecutor(executorID)
}

func (d *Dispatcher) HandleError(ctx context.Context, debugletID *string, err error) {
	d.logger.Error("Got executor error", zap.Stringp("debugletID", debugletID), zap.Error(err))
}

func (d *Dispatcher) HandleResources(ctx context.Context, executorID string, capacity int64) error {
	// TODO
	return nil
}
