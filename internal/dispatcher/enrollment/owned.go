// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

var (
	ErrNodeLimit        = errors.New("an account may register at most ten executors")
	ErrUnknownOwnedNode = errors.New("executor does not belong to this account")
)

// CreateOwned records ownership and issues its first token in one transaction.
// The insertion enforces the account limit in the same SQLite write.
func (s *Store) CreateOwned(ctx context.Context, owner uuid.UUID, id, name string) (token string, expires time.Time, err error) {
	err = s.write(ctx, func(q *database.Queries) error {
		created, err := q.CreateOwnedExecutor(ctx, database.CreateOwnedExecutorParams{
			ExecutorID: id, Uuid: owner, Name: name, CreatedAt: models.NewUTCTime(s.now()),
		})
		if err != nil {
			return err
		}
		if created == 0 {
			return ErrNodeLimit
		}
		token, expires, err = s.issue(ctx, q, id, DefaultLifetime)
		return err
	})
	return
}

// RenewOwned replaces the unused setup token while preserving the installed
// credential. Only successful enrollment replaces that credential.
func (s *Store) RenewOwned(ctx context.Context, owner uuid.UUID, id string) (token string, expires time.Time, err error) {
	err = s.write(ctx, func(q *database.Queries) error {
		_, err := q.GetOwnedExecutor(ctx, database.GetOwnedExecutorParams{Uuid: owner, ExecutorID: id})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownOwnedNode
		}
		if err != nil {
			return err
		}
		token, expires, err = s.issue(ctx, q, id, DefaultLifetime)
		return err
	})
	return
}
