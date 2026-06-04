package dispatcher_test

import (
	"debuglet/internal/dispatcher"
)

// assert interface
var _ dispatcher.ControlHandler = (*dispatcher.Dispatcher)(nil)
