package wasm

import (
	"context"
	"debuglet/internal/executor/ratelimit/app"
	"fmt"
)

// ratelimit blocks until the given environment is allowed to transfer up/down for the given socket and size
func ratelimit(ctx context.Context, env *WasmEnv, direction app.TransferDirection, addr string, size app.Bitrate) error {
	// Blocks until data can be received
	err := env.Limiter.Wait(ctx, direction, env.DebugletID, addr, size)
	if err != nil {
		env.Logger.Warnw("hostReceiveData: wait error", "err", err)
		return fmt.Errorf("receive_data: wait error: %w", err)
	}
	return nil
}
