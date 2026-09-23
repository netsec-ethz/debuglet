package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

var _ scheduler.RunInspection = (*SqliteStorage)(nil)

// InspectRetainedRun reads one stored row without scheduling, finalizing or
// deleting anything. Rows belonging to the caller's current binding are
// excluded, and that exclusion stays distinguishable from an absent row.
func (s *SqliteStorage) InspectRetainedRun(ctx context.Context, id uuid.UUID, current controlsession.Binding) (scheduler.RetainedRun, error) {
	if id == uuid.Nil {
		return scheduler.RetainedRun{}, errors.New("cannot inspect the nil run identity")
	}
	result := scheduler.RetainedRun{Status: scheduler.RetainedRunAbsent, DebugletID: id}
	err := s.local.Inspect(ctx, func(ctx context.Context) error {
		return s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
			row, err := queries.GetDebugletIdentity(ctx, id)
			if errors.Is(err, sql.ErrNoRows) {
				return nil // No stored row carries this identity.
			}
			if err != nil {
				return err
			}
			if row.Uuid != id {
				return fmt.Errorf("stored run identity does not match the requested one")
			}
			stored := controlsession.Binding{Incarnation: row.DispatcherIncarnation, SessionID: row.SessionID}
			if current.Valid() && stored == current {
				result = scheduler.RetainedRun{Status: scheduler.RetainedRunFiltered, DebugletID: id}
				return nil
			}
			result = scheduler.RetainedRun{
				Status:        scheduler.RetainedRunFound,
				DebugletID:    row.Uuid,
				Binding:       stored,
				TransactionID: row.TransactionID,
				StartTime:     row.StartTime.Time,
				StartedAt:     row.StartedAt.Time,
			}
			return nil
		})
	})
	if err != nil {
		return scheduler.RetainedRun{}, err
	}
	return result, nil
}
