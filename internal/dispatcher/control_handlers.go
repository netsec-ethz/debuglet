package dispatcher

import (
	"context"
	"fmt"
	"time"

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
	d.RegisterExecutor(h.ExecutorID, h.Version, h.SourceIP, h.TeslaDelay, h.TeslaAnchorTimestamp, h.TeslaAnchorKey)
	return nil
}

func (d *Dispatcher) HandleHeartbeat(ctx context.Context, hb Heartbeat) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if exec, exists := d.executors[hb.ExecutorID]; exists {
		exec.LastSeen = hb.Timestamp
		exec.Ready = true
	} else {
		return fmt.Errorf("executor '%s' not found", hb.ExecutorID)
	}

	return d.keystore.Store(hb.ExecutorID, hb.TeslaKeyEpoch, hb.TeslaKey)
}

func (d *Dispatcher) HandleDisconnect(executorID string) {
	d.RemoveExecutor(executorID)
}

func (d *Dispatcher) HandleError(ctx context.Context, debugletID *string, err error) {
	d.logger.Error("Got executor error", zap.Stringp("debugletID", debugletID), zap.Error(err))

	if debugletID == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	st, exists := d.debugletStores[*debugletID]
	if !exists {
		return
	}

	st.State = RunStateExited
	st.Err = err.Error()

	for _, conn := range d.connectedLogs[*debugletID] {
		if conn.state != nil {
			select {
			case conn.state <- RunStateExited:
			default:
			}
		}
	}

	for _, dest := range st.Policy.Addresses {
		d.destinations.Remove(*debugletID, dest, st.ExecutorID, st.Policy.FloorBW, st.Policy.CeilBW)
	}
	ctxBg := context.Background()
	d.sendFairshare(ctxBg, st.Policy.Addresses)

	go func() {
		time.Sleep(10 * time.Minute)
		d.mu.Lock()
		delete(d.debugletStores, *debugletID)
		delete(d.connectedLogs, *debugletID)
		d.mu.Unlock()
	}()

	for _, conn := range d.connectedLogs[*debugletID] {
		close(conn.done)
	}
}

func (d *Dispatcher) HandleResources(ctx context.Context, executorID string, capacity int64) error {
	// TODO
	return nil
}
