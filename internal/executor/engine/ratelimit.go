package engine

import (
	"debuglet/internal/executor/resource"
	"fmt"

	"go.uber.org/zap"
)

// ratelimit blocks until the given environment is allowed to transfer up/down for the given socket and size
func ratelimit(env *HostEnvironment, direction resource.TransferDirection, sockID, size int32, sugar *zap.SugaredLogger) error {
	addr := env.handleToAddr[sockID]
	// Greedily update the tracker every time
	executorLimit := env.manager.GetAllowedExecutor(env.sessionID)
	destinationLimit := env.manager.GetAllowedDestination(env.sessionID, addr)
	if destinationLimit == 0 {
		// if there's no destination-specific ratelimit, allow it to use its full executor ratelimitted bandwidth
		destinationLimit = executorLimit
	}
	limits := resource.UsageLimits{
		ExecutorRatelimit:    executorLimit,
		ExecutorBurst:        executorLimit,
		DestinationRatelimit: destinationLimit,
		DestinationBurst:     destinationLimit,
	}
	sugar.Debugw("registering limits", "session_id", env.sessionID, "limits", limits)
	env.tracker.Register(addr, limits)

	// Blocks until data can be received
	err := env.tracker.Wait(env.ctx, direction, addr, int64(size))
	if err != nil {
		sugar.Warnw("hostReceiveData: wait error", "err", err)
		return fmt.Errorf("receive_data: wait error: %w", err)
	}
	return nil
}
