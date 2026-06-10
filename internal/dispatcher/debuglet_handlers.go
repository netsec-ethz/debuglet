package dispatcher

import "context"

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
	// TODO
	return nil
}

func (d *Dispatcher) HandleOutput(ctx context.Context, debugletID string, output []byte) error {
	// TODO
	return nil
}

func (d *Dispatcher) HandleExit(ctx context.Context, debugletID string, exitCode int32, err error) {
	// TODO
}
