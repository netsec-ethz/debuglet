package executor_test

import (
	"debuglet/internal/executor"
	"debuglet/internal/executor/transport"
)

// assert interface
var _ transport.ControlHandler = (*executor.Executor)(nil)
