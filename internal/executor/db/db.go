package db

import (
	"context"
	"debuglet/internal/executor/transport"
)

type Storage interface {
	Insert(transport.Upload) error
	// RegisterOnStart sets the given function as the callback for when a debuglet should be started
	RegisterOnStart(func(context.Context, transport.Upload) error)
	RegisterOnError(func(debugletID string, err error))
	// StartLoop starts the loop that checks if any jobs are to be started and correspondingly calls the registered onStart function
	StartLoop(ctx context.Context) error
}
