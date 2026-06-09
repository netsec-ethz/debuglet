package executor

import (
	"context"
	"debuglet/internal/executor/transport/rpc"
)

func (e *Executor) OnStart(ctx context.Context, spec rpc.Upload) {}
