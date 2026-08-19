package scheduler

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type Scheduler interface {
	Insert(context.Context, Spec) error
	// Remove removes a debuglet from storage preventing it from being started. It returns false if
	// the given ID does not exist in the storage anymore (i.e. the debuglet has already started).
	Remove(ctx context.Context, debugletID uuid.UUID) (bool, error)
	// RegisterOnStart sets the callback function for when a debuglet should be started.
	RegisterOnStart(func(context.Context, Spec))
	// RegisterFailed sets the callback function for when a debuglet fails to start or is not allowed to start anymore.
	RegisterFailed(cb func(context.Context, Spec, error))
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
	DebugletID    uuid.UUID
	StartTime     *time.Time
	Args          []string
	Wasm          []byte
	Policy        Policy
	TransactionID string
}

var (
	// ErrDebugletAlreadyStarted is returned when a debuglet has already started, but the executor was restarted before it could finish.
	ErrDebugletAlreadyStarted = errors.New("debuglet has already started. won't restart")
)
