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
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), 13); err != nil || version != 13 {
		t.Fatalf("migration=%d, %v", version, err)
	}
	got, err := q.GetDebugletByUUID(ctx, run.Uuid)
	if err != nil || !reflect.DeepEqual(got, run) {
		t.Fatalf("migration changed run: %+v, %v", got, err)
	}
	var cancellation int64
	if err := db.QueryRowContext(ctx, "SELECT debuglet_id FROM debuglet_cancellations WHERE debuglet_id = ?", run.ID).Scan(&cancellation); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("migration invented cancellation: %v", err)
	}
}
