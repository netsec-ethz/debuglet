package scheduler

import (
	"context"
	"time"
)

type Scheduler interface {
	Insert(context.Context, Spec) error
	// Remove removes a debuglet from storage preventing it from being started. It returns false if
	// the given ID does not exist in the storage anymore (i.e. the debuglet has already started).
	Remove(ctx context.Context, debugletID string) (bool, error)
	// RegisterOnStart sets the callback function for when a debuglet should be started.
	RegisterOnStart(func(context.Context, Spec))
	// StartLoop starts the loop that checks if any jobs are to be started and correspondingly calls the registered onStart function
	StartLoop(ctx context.Context) error
}

type Policy struct {
	FloorBW     int64
	CeilBW      int64
	Timeout     time.Duration
	Addresses   []string
	RequireICMP bool
	ListenUDP   bool
	ListenTCP   bool
	ListenICMP  bool
	ListenSCION bool
}

type Spec struct {
	DebugletID    string
	StartTime     *time.Time
	Args          []string
	Wasm          []byte
	Policy        Policy
	TransactionID string
}
