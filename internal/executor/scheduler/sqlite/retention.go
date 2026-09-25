package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

var _ scheduler.TerminalRetention = (*SqliteStorage)(nil)

const (
	// maxRetainedDiagnostic bounds the delivery failure kept with a retained
	// event, so a large peer error cannot grow the executor database.
	maxRetainedDiagnostic = 512
	// maxRetainedListing bounds one reconciliation walk.
	maxRetainedListing = 256
)

// RecordTerminal retains the chosen result under the run's immutable identity.
// The first write wins, so a repeated report can never change the result a
// duplicate delivery would confirm.
func (s *SqliteStorage) RecordTerminal(ctx context.Context, event scheduler.TerminalEvent) error {
	if event.DebugletID == uuid.Nil {
		return errors.New("cannot retain a terminal event without a run identity")
	}
	if !event.Binding.Valid() {
		return scheduler.ErrTerminalNotRetained
	}
	message := sql.NullString{}
	if event.ErrorMessage != nil {
		message = sql.NullString{String: *event.ErrorMessage, Valid: true}
	}
	recorded := event.RecordedAt
	if recorded.IsZero() {
		recorded = time.Now()
	}
	return s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
		return queries.RecordDebugletExit(ctx, database.RecordDebugletExitParams{
			DebugletID:            event.DebugletID.String(),
			DispatcherIncarnation: event.Binding.Incarnation,
			SessionID:             event.Binding.SessionID,
			ExitCode:              int64(event.ExitCode),
			ErrorMessage:          message,
			RecordedAt:            database.NewUTCTime(recorded),
		})
	})
}

// NoteTerminalFailure counts one completed delivery attempt. Only the binding
// the run was accepted under may write here, so a replacement session cannot
// touch the events of the session it replaced.
func (s *SqliteStorage) NoteTerminalFailure(ctx context.Context, id uuid.UUID, binding controlsession.Binding, attempt scheduler.TerminalAttempt) error {
	if !binding.Valid() {
		return scheduler.ErrTerminalNotRetained
	}
	if attempt.Attempts < 0 {
		return fmt.Errorf("cannot note %d delivery attempts", attempt.Attempts)
	}
	diagnostic := "delivery failed without a reported cause"
	if attempt.Failure != nil {
		diagnostic = boundDiagnostic(attempt.Failure.Error())
	}
	var affected int64
	if err := s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
		var err error
		affected, err = queries.NoteDebugletExitFailure(ctx, database.NoteDebugletExitFailureParams{
			Attempts:              attempt.Attempts,
			LastAttemptAt:         database.NewUTCTime(time.Now()),
			LastError:             diagnostic,
			Rejected:              attempt.Rejected,
			DebugletID:            id.String(),
			DispatcherIncarnation: binding.Incarnation,
			SessionID:             binding.SessionID,
		})
		return err
	}); err != nil {
		return fmt.Errorf("failed to note terminal delivery attempt for %s: %w", id, err)
	}
	if affected == 0 {
		return scheduler.ErrTerminalNotRetained
	}
	return nil
}

// ReleaseTerminal ends retention once an acknowledgement has been observed.
// Its own commit is the durable record that the result is no longer pending.
func (s *SqliteStorage) ReleaseTerminal(ctx context.Context, id uuid.UUID, binding controlsession.Binding) error {
	if !binding.Valid() {
		return scheduler.ErrTerminalNotRetained
	}
	var affected int64
	if err := s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
		var err error
		affected, err = queries.ReleaseDebugletExit(ctx, database.ReleaseDebugletExitParams{
			DebugletID:            id.String(),
			DispatcherIncarnation: binding.Incarnation,
			SessionID:             binding.SessionID,
		})
		return err
	}); err != nil {
		return fmt.Errorf("failed to release terminal event for %s: %w", id, err)
	}
	if affected == 0 {
		return scheduler.ErrTerminalNotRetained
	}
	return nil
}

// RetainedTerminal answers whether one run still has an unreconciled result.
func (s *SqliteStorage) RetainedTerminal(ctx context.Context, id uuid.UUID) (scheduler.TerminalEvent, bool, error) {
	var event scheduler.TerminalEvent
	found := false
	err := s.local.Inspect(ctx, func(ctx context.Context) error {
		return s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
			row, err := queries.GetDebugletExit(ctx, id.String())
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			event, err = terminalEvent(row)
			if err != nil {
				return err
			}
			found = true
			return nil
		})
	})
	if err != nil {
		return scheduler.TerminalEvent{}, false, err
	}
	return event, found, nil
}

// ListRetainedTerminals reads the oldest events the given binding can still
// deliver. Filtering happens in the query, so events belonging to replaced
// sessions and events the dispatcher already rejected cannot occupy the limit.
func (s *SqliteStorage) ListRetainedTerminals(ctx context.Context, binding controlsession.Binding, limit int64) ([]scheduler.TerminalEvent, error) {
	if limit <= 0 || !binding.Valid() {
		return nil, nil
	}
	return s.listTerminals(ctx, func(ctx context.Context, queries *database.Queries) ([]database.DebugletExit, error) {
		return queries.ListDebugletExitsForBinding(ctx, database.ListDebugletExitsForBindingParams{
			DispatcherIncarnation: binding.Incarnation,
			SessionID:             binding.SessionID,
			Limit:                 min(limit, maxRetainedListing),
		})
	})
}

// ListAllRetainedTerminals reads the oldest unreconciled events whatever their
// binding or rejection, which is what an operator inspecting the executor sees.
func (s *SqliteStorage) ListAllRetainedTerminals(ctx context.Context, limit int64) ([]scheduler.TerminalEvent, error) {
	if limit <= 0 {
		return nil, nil
	}
	return s.listTerminals(ctx, func(ctx context.Context, queries *database.Queries) ([]database.DebugletExit, error) {
		return queries.ListDebugletExits(ctx, min(limit, maxRetainedListing))
	})
}

func (s *SqliteStorage) listTerminals(ctx context.Context, read func(context.Context, *database.Queries) ([]database.DebugletExit, error)) ([]scheduler.TerminalEvent, error) {
	var events []scheduler.TerminalEvent
	err := s.local.Inspect(ctx, func(ctx context.Context) error {
		return s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
			rows, err := read(ctx, queries)
			if err != nil {
				return err
			}
			events = make([]scheduler.TerminalEvent, 0, len(rows))
			for _, row := range rows {
				event, err := terminalEvent(row)
				if err != nil {
					return err
				}
				events = append(events, event)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// RetainedTerminalCount reports the unreconciled events observed by the latest
// serialized restore, alongside QuarantinedCount.
func (s *SqliteStorage) RetainedTerminalCount() int64 { return s.retainedExits.Load() }

func terminalEvent(row database.DebugletExit) (scheduler.TerminalEvent, error) {
	id, err := uuid.Parse(row.DebugletID)
	if err != nil || id == uuid.Nil || id.String() != row.DebugletID {
		return scheduler.TerminalEvent{}, fmt.Errorf("retained terminal event has an unusable run identity")
	}
	if row.ExitCode > math.MaxInt32 || row.ExitCode < math.MinInt32 {
		return scheduler.TerminalEvent{}, fmt.Errorf("retained terminal event %s has an unusable exit code", id)
	}
	event := scheduler.TerminalEvent{
		DebugletID:    id,
		Binding:       controlsession.Binding{Incarnation: row.DispatcherIncarnation, SessionID: row.SessionID},
		ExitCode:      int32(row.ExitCode),
		RecordedAt:    row.RecordedAt.Time,
		Attempts:      row.Attempts,
		LastAttemptAt: row.LastAttemptAt.Time,
		LastError:     row.LastError,
		Rejected:      row.Rejected,
	}
	if row.ErrorMessage.Valid {
		message := row.ErrorMessage.String
		event.ErrorMessage = &message
	}
	return event, nil
}

// boundDiagnostic keeps a retained diagnostic small and valid UTF-8.
func boundDiagnostic(text string) string {
	if len(text) <= maxRetainedDiagnostic {
		return text
	}
	cut := maxRetainedDiagnostic
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "…"
}
