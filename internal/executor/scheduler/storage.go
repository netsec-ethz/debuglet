package scheduler

import (
	"context"
	"debuglet/internal/executor/transport/rpc"
)

type Scheduler interface {
	Insert(rpc.Spec) error
	// Remove removes a debuglet from storage preventing it from being started. It returns false if
	// the given ID does not exist in the storage anymore (i.e. the debuglet has already started).
	Remove(debugletID string) bool
	// RegisterOnStart sets the callback function for when a debuglet should be started
	RegisterOnStart(func(context.Context, rpc.Spec))
	// StartLoop starts the loop that checks if any jobs are to be started and correspondingly calls the registered onStart function
	StartLoop(ctx context.Context) error
}
