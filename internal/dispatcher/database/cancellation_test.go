// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestCancellationMigrationPreservesRunsWithoutInventingRequests(t *testing.T) {
	ctx, db := cbOpen(t, 11)
	q := database.New(db)
	run := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), sqlitedb.Latest); err != nil || version != 13 {
		t.Fatalf("migration=%d, %v", version, err)
	}
	got, err := q.GetDebugletByUUID(ctx, run.Uuid)
	if err != nil || !reflect.DeepEqual(got, run) {
		t.Fatalf("migration changed run: %+v, %v", got, err)
	}
	if _, err := q.GetCancellation(ctx, run.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("migration invented cancellation: %v", err)
	}
}
