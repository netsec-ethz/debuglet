// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestTerminalCleanupMigrationPreservesExistingResults(t *testing.T) {
	ctx, db := cbOpen(t, 11)
	q := database.New(db)
	run := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	terminal, err := q.CompleteDebuglet(ctx, database.CompleteDebugletParams{
		Uuid: run.Uuid, ExecutorID: run.ExecutorID, DispatcherIncarnation: run.DispatcherIncarnation,
		SessionID: run.SessionID, ExitedState: models.RunStateExited,
		Error: sql.NullString{String: "historical result", Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), sqlitedb.Latest); err != nil || version != 13 {
		t.Fatalf("migration=%d, %v", version, err)
	}
	got, err := q.GetDebugletByUUID(ctx, run.Uuid)
	if err != nil || !reflect.DeepEqual(got, terminal) {
		t.Fatalf("migration changed result: %+v, %v", got, err)
	}
	if _, err := q.GetTerminalCleanup(ctx, run.Uuid); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("migration invented historical cleanup: %v", err)
	}
}
