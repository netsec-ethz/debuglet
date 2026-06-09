package executor

import (
	"context"
	"debuglet/internal/executor/transport/rpc"
	"debuglet/protocol"

	"go.uber.org/zap"
)

func (e *Executor) OnStart(ctx context.Context, debuglet rpc.Spec) {
	ctx, cancel := context.WithCancelCause(ctx)

	client := rpc.NewDebugletClient(*e.control.GRPCClient(), debuglet, e.cfg.ExecutorID)
	e.running[debuglet.DebugletID] = client

	go func() {
		if err := client.Listen(ctx); err != nil {
			cancel(err)
			// TODO: failed debuglets are still stored in e.running. Makes sense to move/store elsewhere
		}
	}()

	select {
	case <-ctx.Done():
		e.logger.Error("Failed to start debuglet GRPC session", zap.Error(context.Cause(ctx)))
		return
	case <-client.Ready():
	}

	client.SetState(protocol.RunState_RUN_STATE_INITIALIZING)

	// TODO: initialize debuglet

	client.SetState(protocol.RunState_RUN_STATE_STARTED)

	// TODO: run debuglet

	<-ctx.Done()
	// TODO: proper mutex for deleting/adding debuglet spec while handling aborts
	delete(e.running, debuglet.DebugletID)
}
