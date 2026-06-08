package dispatcher

import (
	"context"
)

type ControlHandler interface {
	HandleHello(ctx context.Context, h Hello) error
	HandleHeartbeat(ctx context.Context, hb Heartbeat) error
	HandleDisconnect(ctx context.Context, executorID string)
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
