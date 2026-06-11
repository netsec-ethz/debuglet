package dispatcher

import (
	"context"
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
	HandleState(ctx context.Context, debugletID, executorID string, state DebugletRunState) error
	HandleOutput(ctx context.Context, debugletID string, output []byte) error
	// HandleExit is called when a debuglet finishes, errors, or has been aborted
	HandleExit(debugletID string, exitCode int32, err error)
}

func (d *Dispatcher) HandleState(ctx context.Context, debugletID, executorID string, state DebugletRunState) error {
	d.logger.Debug("Received debuglet state update", zap.String("debugletID", debugletID), zap.String("executorID", executorID), zap.Int("state", state))
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
	d.mu.Unlock()

	d.mu.RLock()
	connections := d.connectedLogs[debugletID]
	d.mu.RUnlock()
	for _, conn := range connections {
		conn.logs <- output
	}
	return nil
}

func (d *Dispatcher) HandleExit(debugletID string, exitCode int32, err error) {
	d.logger.Debug("Received debuglet exit", zap.String("debugletID", debugletID), zap.Int32("exitCode", exitCode), zap.Error(err))
	d.mu.Lock()
	delete(d.debugletStores, debugletID)
	for _, conn := range d.connectedLogs[debugletID] {
		close(conn.done)
	}
	d.mu.Unlock()
}
