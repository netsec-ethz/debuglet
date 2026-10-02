// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestIdentityUpgradePreservesAccountAndSession(t *testing.T) {
	ctx, db := cbOpen(t, 16)
	q := database.New(db)
	user, err := q.CreateUserWithRole(ctx, database.CreateUserWithRoleParams{Uuid: uuid.New(), Name: "existing researcher", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	now := models.NewUTCTime(time.Now().UTC().Truncate(time.Second))
	if _, err := db.ExecContext(ctx, "INSERT INTO oauth_identities (provider,subject,user_id,login,created_at,updated_at) VALUES (?,?,?,?,?,?)", "github", "42", user.ID, "researcher", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO sessions (selector,verifier_hash,csrf_hash,user_id,created_at,expires_at,revoked) VALUES (?,?,?,?,?,?,0)", "existing", []byte("digest"), []byte("csrf"), user.ID, now, models.NewUTCTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), 18); err != nil || version != 18 {
		t.Fatalf("upgrade=%d: %v", version, err)
	}
	if owner, err := q.FindExternalIdentity(ctx, database.FindExternalIdentityParams{Issuer: "https://github.com", Subject: "42"}); err != nil || owner != user.ID {
		t.Fatalf("identity owner=%d: %v", owner, err)
	}
	session, err := q.GetSessionBySelector(ctx, "existing")
	if err != nil {
		t.Fatal(err)
	}
	if session.Uuid != user.Uuid || session.Kind != "browser" || !session.AuthenticatedAt.Equal(now.Time) {
		t.Fatalf("upgraded session changed: %+v", session)
	}
}
