package dispatcher

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type DispatcherDebugletHandler interface {
	HandleState(ctx context.Context, debugletID, executorID string, state DebugletRunState, policy DebugletPolicy) error
	HandleOutput(ctx context.Context, debugletID string, output []byte) error
	// HandleExit is called when a debuglet finishes, errors, or has been aborted
	HandleExit(debugletID string, exitCode int32, err error)
}

func (d *Dispatcher) HandleState(ctx context.Context, debugletID, executorID string, state DebugletRunState, policy DebugletPolicy) error {
	d.logger.Debug("Received debuglet state update", zap.String("debugletID", debugletID), zap.String("executorID", executorID), zap.String("state", state.String()))

	d.mu.Lock()
	if store, ok := d.debugletStores[debugletID]; ok {
		store.State = state
		for _, conn := range d.connectedLogs[debugletID] {
			if conn.state != nil {
				select {
				case conn.state <- state:
				default:
				}
			}
		}
	}
	d.mu.Unlock()

	if state == RunStateInitializing {
		d.mu.Lock()
		defer d.mu.Unlock()

		// check if any destination is overloaded (only accounts for the floor bandwidth)
		d.logger.Debug("Checking debuglet capacity usage", zap.String("debugletID", debugletID), zap.Strings("destinations", policy.Addresses), zap.String("floorBW", policy.FloorBW.String()), zap.String("ceilBW", policy.CeilBW.String()))
		for _, dest := range policy.Addresses {
			if err := d.destinations.CheckCapacity(dest, policy.FloorBW); err != nil {
				d.sender.AbortDebuglet(ctx, executorID, debugletID, "not enough capacity")
				return err
			}
		}
		for _, dest := range policy.Addresses {
			if err := d.destinations.Insert(debugletID, dest, executorID, policy.FloorBW, policy.CeilBW); err != nil {
				d.sender.AbortDebuglet(ctx, executorID, debugletID, err.Error())
				return err
			}
		}
		d.sendFairshare(ctx, policy.Addresses)
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
	store.Logs = append(store.Logs, output...)

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
	defer d.mu.Unlock()

	if st, exists := d.debugletStores[debugletID]; exists {
		st.State = RunStateExited
		if err != nil {
			st.Err = err.Error()
		}
		for _, conn := range d.connectedLogs[debugletID] {
			if conn.state != nil {
				select {
				case conn.state <- RunStateExited:
				default:
				}
			}
		}

		for _, dest := range st.Policy.Addresses {
			d.destinations.Remove(debugletID, dest, st.ExecutorID, st.Policy.FloorBW, st.Policy.CeilBW)
		}
		ctx := context.Background() // debuglet stream context is already cancelled at this point
		d.sendFairshare(ctx, st.Policy.Addresses)

		// remove debuglet store 10 minutes later
		go func() {
			time.Sleep(10 * time.Minute)
			d.mu.Lock()
			delete(d.debugletStores, debugletID)
			delete(d.connectedLogs, debugletID)
			d.mu.Unlock()
		}()
	}
	for _, conn := range d.connectedLogs[debugletID] {
		close(conn.done)
	}
}

func (d *Dispatcher) sendFairshare(ctx context.Context, dests []string) {
	var perExec map[string][]LimitUpdate = make(map[string][]LimitUpdate)
	for _, dest := range dests {
		for eID, limit := range d.destinations.Fairshare(dest) {
			d.logger.Debug("New fairshared update", zap.String("executorID", eID), zap.String("newLimit", limit.String()))
			perExec[eID] = append(perExec[eID], LimitUpdate{Address: dest, Limit: limit})
		}
	}
	for exec, updates := range perExec {
		go func(exec string, updates []LimitUpdate) {
			if err := d.sender.DestinationUpdates(ctx, exec, updates); err != nil {
				d.logger.Error("Failed to send update", zap.String("executorID", exec), zap.Objects("destination", updates), zap.Error(err))
			}
		}(exec, updates)
	}
}
