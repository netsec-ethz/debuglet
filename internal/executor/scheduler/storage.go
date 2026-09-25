// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package scheduler

import (
	"context"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"time"

	"github.com/google/uuid"
)

// Completion records local resource cleanup after an owned callback joins its
// execution and workers. Execution/reporting outcomes are separate.
type Completion struct {
	CleanupErr error
}

type StartFunc func(context.Context, Spec) Completion
type FailedFunc func(context.Context, Spec, error) Completion

// AdmissionGuard commits a bounded in-memory core transition only while its
// original control binding is eligible. The core holds its mutex before the
// session guard; commit must never do I/O, cancel, close or wait for work.
type AdmissionGuard func(controlsession.Binding, func()) error

// Admission supplies construction-fixed authority for new persistence
// reservations and queue promotion. Every constructor requires both, so a core
// always commits under a guard; a caller whose subject is not admission
// supplies guards that always commit.
type Admission struct {
	Insert AdmissionGuard
	Start  AdmissionGuard
}

// CleanupTimeout bounds an individual resource-cleanup/report operation or SQL
// statement after connection admission. Owned finalization may wait longer for
// a connection; caller deadlines separately bound Cancel and Shutdown joins.
const CleanupTimeout = 5 * time.Second

// Scheduler is what one session may ask of its storage. Cancellation is offered
// only as CancelBound, so no request can reach a run whose control binding it
// does not name; the unbound and queue-only deletions stay on the backends for
// their own tests.
type Scheduler interface {
	Insert(context.Context, Spec) error
	// CancelBound compares immutable run ownership atomically before cancellation.
	// It never cancels a later admission after observing an absent owner.
	CancelBound(context.Context, uuid.UUID, controlsession.Binding, error) (bool, error)
	// RegisterOnStart sets the callback function for when a debuglet should be started.
	RegisterOnStart(StartFunc)
	// RegisterFailed sets the callback function for when a debuglet fails to start or is not allowed to start anymore.
	RegisterFailed(FailedFunc)
	// StartLoop starts the loop that checks if any jobs are to be started and correspondingly calls the registered onStart function
	StartLoop(ctx context.Context) error
	// Shutdown closes new admission and joins owned active operations. Accepted
	// queued rows remain recoverable; existing insertion reservations complete.
	Shutdown(context.Context) error
}

type Policy struct {
	FloorBW     int64
	CeilBW      int64
	Timeout     time.Duration
	Addresses   []string
	RequireICMP bool
	ListenUDP   bool
	ListenTCP   bool
	ListenSCION bool
}

// RestoreEligibility is an explicit startup policy. Invalid bindings and a nil
// policy always quarantine a stored row before any execution/failure callback.
type RestoreEligibility func(controlsession.Binding) bool

type Spec struct {
	Binding       controlsession.Binding
	DebugletID    uuid.UUID
	StartTime     *time.Time
	Args          []string
	Wasm          []byte
	Policy        Policy
	TransactionID string
}

var (
	ErrClosed          = errors.New("scheduler is shut down")
	ErrBindingMismatch = errors.New("debuglet belongs to another control session")
	// ErrDebugletAlreadyStarted is returned when a debuglet has already started, but the executor was restarted before it could finish.
	ErrDebugletAlreadyStarted = errors.New("debuglet has already started. won't restart")
)
