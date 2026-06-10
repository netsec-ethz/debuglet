package dispatcher

import (
	"context"

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
	HandleExit(ctx context.Context, debugletID string, exitCode int32, err error)
}

func (d *Dispatcher) HandleState(ctx context.Context, debugletID, executorID string, state DebugletRunState) error {
	if state == RunStateInitializing {
		d.debugletLogs[debugletID] = []byte{}
	}
	d.logger.Debug("Received debuglet state update", zap.String("debugletID", debugletID), zap.String("executorID", executorID), zap.Int("state", state))
	return nil
}

func (d *Dispatcher) HandleOutput(ctx context.Context, debugletID string, output []byte) error {
	d.logger.Debug("Received debuglet output", zap.String("debugletID", debugletID), zap.Int("outputSize", len(output)))

	d.mu.Lock()
	d.debugletLogs[debugletID] = append(d.debugletLogs[debugletID], output...)
	d.mu.Unlock()

	// NOTE: this lock might block for too long
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, conn := range d.connectedLogs[debugletID] {
		conn.logs <- output
	}
	return nil
}

func (d *Dispatcher) HandleExit(ctx context.Context, debugletID string, exitCode int32, err error) {
	d.logger.Debug("Received debuglet exit", zap.String("debugletID", debugletID), zap.Int32("exitCode", exitCode), zap.Error(err))
	d.mu.Lock()
	delete(d.debugletLogs, debugletID)
	for _, conn := range d.connectedLogs[debugletID] {
		close(conn.done)
	}
	d.mu.Unlock()
}
