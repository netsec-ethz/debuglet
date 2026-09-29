// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestResultProvenanceMigrationAndImmutability(t *testing.T) {
	ctx, db := cbOpen(t, 10)
	q := database.New(db)
	legacy := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), sqlitedb.Latest); err != nil || version != 14 {
		t.Fatalf("migration=%d, %v", version, err)
	}
	if _, err := q.GetDebugletProvenance(ctx, legacy.Uuid); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("invented legacy provenance: %v", err)
	}
	const saved = `{"source":"admission", "argument":"測定"}`
	if err := q.CreateDebugletProvenance(ctx, database.CreateDebugletProvenanceParams{DebugletID: legacy.ID, Document: saved}); err != nil {
		t.Fatal(err)
	}
	if size, err := q.GetDebugletProvenanceSize(ctx, legacy.ID); err != nil || !size.Valid || size.Int64 != int64(len(saved)) {
		t.Fatalf("provenance byte size=%+v, %v", size, err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE debuglet_provenance SET document = '{}' WHERE debuglet_id = ?", legacy.ID); err == nil {
		t.Fatal("rewrote immutable provenance")
	}
	if got, err := q.GetDebugletProvenance(ctx, legacy.Uuid); err != nil || got != saved {
		t.Fatalf("saved=%s, %v", got, err)
	}
	other := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.WithTx(tx).CreateDebugletProvenance(ctx, database.CreateDebugletProvenanceParams{DebugletID: other.ID, Document: saved}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetDebugletProvenance(ctx, other.Uuid); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rollback kept provenance: %v", err)
	}
}
