// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestOwnerDisplayMigrationPreservesRegisteredOwners(t *testing.T) {
	ctx, db := cbOpen(t, 30)
	if _, err := db.ExecContext(ctx, `INSERT INTO users (uuid,name) VALUES (x'00112233445566778899aabbccddeeff','owner')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO owned_executors (executor_id,user_id,name,created_at) VALUES ('node',1,'private name',CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	var name, display, city, country, network string
	if err := db.QueryRowContext(ctx, `SELECT name,display_name,city,country,network FROM owned_executors WHERE executor_id='node'`).Scan(&name, &display, &city, &country, &network); err != nil {
		t.Fatal(err)
	}
	if name != "private name" || display+city+country+network != "" {
		t.Fatal("migration changed ownership label or invented display metadata")
	}
}
