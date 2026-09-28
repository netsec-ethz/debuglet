// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// Like withDatabase, a finalizer's SQL budget begins after pool admission.
func (s *SqliteStorage) withTransaction(ctx context.Context, work func(context.Context, *sql.Tx, *database.Queries) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	executionCtx, cancel := context.WithTimeout(ctx, scheduler.CleanupTimeout)
	defer cancel()
	tx, err := conn.BeginTx(executionCtx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var statements database.DBTX = tx
	if s.decorate != nil {
		statements = s.decorate(statements)
	}
	if err := work(executionCtx, tx, database.New(statements)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SqliteStorage) finalizeWithOutput(ctx context.Context, id uuid.UUID) error {
	return s.withTransaction(ctx, func(ctx context.Context, _ *sql.Tx, q *database.Queries) error {
		identity, err := q.GetDebugletIdentity(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if identity.StartedAt.IsZero() {
			output, err := q.GetOutputRun(ctx, id.String())
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err == nil {
				if output.DispatcherIncarnation != identity.DispatcherIncarnation || output.SessionID != identity.SessionID {
					return scheduler.ErrBindingMismatch
				}
				// The owned canonical row proves no producer started. Missing rows
				// or output metadata never establish that fact. Preserve any prefix
				// or end already recorded by an executor callback.
				if output.OutputVersion == pb.OutputVersion && output.Status == "open" && output.LastSequence == 0 {
					if err := q.FinishOutputRun(ctx, database.FinishOutputRunParams{RunID: id.String(), Status: "complete"}); err != nil {
						return err
					}
				}
			}
		}
		return q.DeleteDebuglet(ctx, id)
	})
}
