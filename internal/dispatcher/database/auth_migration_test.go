// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestAuthMigrationPreservesUnmappedOwnershipWithoutCreatingCredentials(t *testing.T) {
	ctx, db := cbOpen(t, 5)
	q := database.New(db)
	var owners [2]struct {
		id   int64
		uuid uuid.UUID
		run  uuid.UUID
	}
	for i := range owners {
		owner := &owners[i]
		owner.uuid = uuid.New()
		if err := db.QueryRowContext(ctx, "INSERT INTO users (uuid,name) VALUES (?,?) RETURNING id", owner.uuid, "same display name").Scan(&owner.id); err != nil {
			t.Fatal(err)
		}
		owner.run = cbCreate(t, ctx, q, "", "").Uuid
		if err := q.InsertDebugletUser(ctx, database.InsertDebugletUserParams{DebUuid: owner.run, UserUuid: owner.uuid}); err != nil {
			t.Fatal(err)
		}
	}
	unowned := cbCreate(t, ctx, q, "", "")
	if _, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	for _, owner := range owners {
		user, err := q.GetUserByUUID(ctx, owner.uuid)
		if err != nil || user.ID != owner.id || user.Uuid != owner.uuid || user.Name != "same display name" || user.Role != "user" {
			t.Fatalf("legacy account changed: %+v: %v", user, err)
		}
		got, err := q.GetDebugletOwnerUUID(ctx, owner.run)
		if err != nil || got != owner.uuid {
			t.Fatalf("run owner = %s, want %s: %v", got, owner.uuid, err)
		}
		runs, err := q.ListDebugletsByUserUUID(ctx, database.ListDebugletsByUserUUIDParams{Uuid: owner.uuid, Limit: 10})
		if err != nil || len(runs) != 1 || runs[0].Uuid != owner.run {
			t.Fatalf("legacy ownership was lost or joined by display name: %+v: %v", runs, err)
		}
	}
	if _, err := q.GetDebugletOwnerUUID(ctx, unowned.Uuid); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unowned run acquired an owner: %v", err)
	}
	for _, table := range []string{"user_credentials", "sessions", "oauth_identities"} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("migration invented %d %s rows for unmapped accounts", count, table)
		}
	}
}
