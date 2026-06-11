package dispatcher

import (
	"context"
	"debuglet/internal/dispatcher/resource"
	"fmt"

	"go.uber.org/zap"
)

type DebugletRunState = int

const (
	RunStateUnspecified = iota
	RunStateInitializing
	RunStateStarted
)

type DispatcherDebugletHandler interface {
	HandleState(ctx context.Context, debugletID, executorID string, state DebugletRunState, policy DebugletPolicy) error
	HandleOutput(ctx context.Context, debugletID string, output []byte) error
	// HandleExit is called when a debuglet finishes, errors, or has been aborted
	HandleExit(debugletID string, exitCode int32, err error)
}

func (d *Dispatcher) HandleState(ctx context.Context, debugletID, executorID string, state DebugletRunState, policy DebugletPolicy) error {
	d.logger.Debug("Received debuglet state update", zap.String("debugletID", debugletID), zap.String("executorID", executorID), zap.Int("state", state))

	if state == RunStateInitializing {
		d.mu.Lock()
		defer d.mu.Unlock()

		// check if any destination is overloaded (only accounts for the floor bandwidth)
		// TODO: Determine if capacity should even be checked here. This can cause a delayed debuglet to fail to start
		for _, dest := range policy.Addresses {
			if err := d.destinations.CheckCapacity(dest, resource.Bitrate(policy.FloorBW)); err != nil {
				return err
			}
		}

		// insert
		d.debugletStores[debugletID] = &debugletStore{
			logs:       []byte{},
			policy:     policy,
			executorID: executorID,
		}
		for _, dest := range policy.Addresses {
			d.destinations.Insert(dest, executorID, policy.FloorBW, policy.CeilBW)

			for eID, limit := range d.destinations.Fairshare(dest) {
				_ = eID
				_ = limit
				// TODO: send updates
				// d.sender.DestinationUpdates(ctx, )
			}
		}
	}
	return nil
}

func (d *Dispatcher) HandleOutput(ctx context.Context, debugletID string, output []byte) error {
	d.logger.Debug("Received debuglet output", zap.String("debugletID", debugletID), zap.Int("outputSize", len(output)))

	d.mu.Lock()
	store, exists := d.debugletStores[debugletID]
	if !exists {
		d.mu.Unlock()
		return fmt.Errorf("debuglet '%s' not found", debugletID)
	}
	store.logs = append(store.logs, output...)

	connections := d.connectedLogs[debugletID]
	d.mu.Unlock()

	for _, conn := range connections {
		conn.logs <- output
	}
	return nil
}

func (d *Dispatcher) HandleExit(debugletID string, exitCode int32, err error) {
	d.logger.Debug("Received debuglet exit", zap.String("debugletID", debugletID), zap.Int32("exitCode", exitCode), zap.Error(err))
	d.mu.Lock()
	if st, exists := d.debugletStores[debugletID]; exists {
		for _, dest := range st.policy.Addresses {
			d.destinations.Remove(dest, st.executorID, st.policy.FloorBW, st.policy.CeilBW)
		}
	}
	delete(d.debugletStores, debugletID)
	for _, conn := range d.connectedLogs[debugletID] {
		close(conn.done)
	}
	d.mu.Unlock()
}
