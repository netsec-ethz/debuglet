package executor

import (
	"context"
	"debuglet/internal/executor/transport"
)

func (e *Executor) OnStart(ctx context.Context, spec transport.Upload) {}
