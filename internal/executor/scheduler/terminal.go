package scheduler

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
)

// TerminalEvent is the terminal result an executor selected for one run,
// retained under that run's immutable identity and its original control
// binding. It is written before execution storage is deleted, so a lost
// response or connection still leaves evidence of what the executor decided
// and of how far delivery got.
type TerminalEvent struct {
	DebugletID   uuid.UUID
	Binding      controlsession.Binding
	ExitCode     int32
	ErrorMessage *string
	RecordedAt   time.Time
	// Attempts counts completed delivery attempts. Zero means the event was
	// retained but never sent; a positive count means the dispatcher may
	// already hold the same result, which its duplicate handling absorbs.
	Attempts      int64
	LastAttemptAt time.Time
	LastError     string
	// Rejected marks a cause the dispatcher will not accept on any retry. The
	// event stays as evidence and leaves the reconciliation set.
	Rejected bool
}

// TerminalAttempt records what one delivery pass learned about an event.
type TerminalAttempt struct {
	// Attempts counts the requests this pass actually sent.
	Attempts int64
	// Rejected reports a permanent refusal rather than a transient failure.
	Rejected bool
	Failure  error
}

// ErrTerminalNotRetained reports that no retained event with the requested
// identity belongs to the supplied binding. A replaced session therefore
// cannot alter or release the events of the session it replaced.
var ErrTerminalNotRetained = errors.New("terminal event is not retained under this control binding")

// TerminalRetention is implemented by backends that retain terminal results
// across restarts. Retention ends exactly when a durable acknowledgement is
// known: the delivery that observed it releases the event, and everything that
// is still retained is unreconciled and inspectable.
//
// Recording, noting and releasing are single statements which do not reserve a
// backend operation, so a caller must keep the storage alive across them: the
// reporting path runs inside the owned callback Shutdown joins, and the
// reconciliation path runs inside a session worker joined before its transport
// and database are closed. ListRetainedTerminals reserves a backend operation of
// its own and is therefore joined by Shutdown without such a caller.
type TerminalRetention interface {
	// RecordTerminal retains the chosen result. It is idempotent under the run
	// identity and never rewrites an already retained result.
	RecordTerminal(context.Context, TerminalEvent) error
	// NoteTerminalFailure records what one failed delivery pass learned,
	// including its bounded cause. Zero attempts means the pass never reached
	// the dispatcher at all.
	NoteTerminalFailure(ctx context.Context, id uuid.UUID, binding controlsession.Binding, attempt TerminalAttempt) error
	// ReleaseTerminal ends retention after an acknowledgement was observed.
	ReleaseTerminal(ctx context.Context, id uuid.UUID, binding controlsession.Binding) error
	// ListRetainedTerminals reads at most limit events the given binding can
	// still deliver, oldest first. Rejected events and the events of other
	// sessions are excluded, so work no session can finish cannot crowd out
	// work that a session can.
	ListRetainedTerminals(ctx context.Context, binding controlsession.Binding, limit int64) ([]TerminalEvent, error)
}
