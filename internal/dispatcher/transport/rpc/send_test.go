package rpc_test

import (
	"debuglet/internal/dispatcher"
	"debuglet/internal/dispatcher/transport/rpc"
)

// assert interface
var _ dispatcher.ExecutorSender = (*rpc.Server)(nil)
