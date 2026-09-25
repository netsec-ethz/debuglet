package scheduler

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
)

// RetainedRunStatus classifies a retained-run point lookup. A miss caused by
// the current-binding filter is deliberately distinct from proof that no
// stored row with that identity exists.
type RetainedRunStatus uint8

const (
	// RetainedRunUnknown is never returned by a successful lookup.
	RetainedRunUnknown RetainedRunStatus = iota
	// RetainedRunFound reports validated metadata for a retained row.
	RetainedRunFound
	// RetainedRunFiltered reports that a stored row exists but belongs to the
	// caller's current control binding, so it is not retained work.
	RetainedRunFiltered
	// RetainedRunAbsent reports that no stored row has this identity.
	RetainedRunAbsent
)

func (s RetainedRunStatus) String() string {
	switch s {
	case RetainedRunFound:
		return "found"
	case RetainedRunFiltered:
		return "filtered"
	case RetainedRunAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// RetainedRun is the identity half of a stored run: who owned it, whether it
// was ever started, and when it was due. It never carries the guest program.
type RetainedRun struct {
	Status        RetainedRunStatus
	DebugletID    uuid.UUID
	Binding       controlsession.Binding
	TransactionID string
	StartTime     time.Time
	StartedAt     time.Time
}

// Started reports whether the stored row carries a start marker.
func (r RetainedRun) Started() bool { return !r.StartedAt.IsZero() }

// RunInspection is implemented by backends that can answer a bounded point
// lookup for one retained run without scheduling, finalizing or deleting it.
type RunInspection interface {
	// InspectRetainedRun reads one stored row, excluding rows that belong to
	// the supplied current binding. The reader is owned for the whole call:
	// caller cancellation bounds the caller's wait, never the backend's use of
	// its connection.
	InspectRetainedRun(ctx context.Context, id uuid.UUID, current controlsession.Binding) (RetainedRun, error)
}
