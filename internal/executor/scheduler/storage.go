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
	// RegisterOnStart sets the callback function for when a debuglet should be started.
	// The preRunLock is to be closed when the receiver has taken over ownership of the debuglet.
	// Without it, if a schedular calls OnStart in a new goroutine while removing the debuglet from
	// its storage, there is a brief race condition where a debuglet is neither in the scheduler storage
	// nor marked as being actively run by the executor.
	RegisterOnStart(func(ctx context.Context, debuglet rpc.Spec, preRunLock chan<- struct{}))
	// StartLoop starts the loop that checks if any jobs are to be started and correspondingly calls the registered onStart function
	StartLoop(ctx context.Context) error
}
