package dispatcher

import "context"

func (d *Dispatcher) HandleHello(ctx context.Context, h Hello) error {
	return nil
}
func (d *Dispatcher) HandleHeartbeat(ctx context.Context, hb Heartbeat) error {
	return nil
}
func (d *Dispatcher) HandleDisconnect(ctx context.Context, executorID string) {
}
