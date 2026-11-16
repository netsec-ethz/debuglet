// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestNativeMigrationPreservesExistingCommunityFunds(t *testing.T) {
	for _, version := range []int64{35, 36} {
		t.Run(string(rune('A'+version-35)), func(t *testing.T) {
			db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "prior.sqlite"), sqlitedb.Create())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err = sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), version); err != nil {
				t.Fatal(err)
			}
			q := database.New(db)
			owner, err := q.CreateUser(t.Context(), database.CreateUserParams{Uuid: uuid.New(), Name: "owner"})
			if err != nil {
				t.Fatal(err)
			}
			for _, stmt := range []string{`INSERT INTO communities(id,name,description,created_by,created_at) VALUES('community','group','',1,0)`, `INSERT INTO community_projects(id,community_id,name,description,created_by,created_at) VALUES('project','community','work','',1,0)`} {
				if _, err = db.Exec(stmt); err != nil {
					t.Fatal(err)
				}
			}
			if owner.ID != 1 {
				t.Fatal("unexpected first user")
			}
			for _, id := range []string{"deposit", "run"} {
				if _, err = q.CreateTransaction(t.Context(), database.CreateTransactionParams{ID: id, Price: 10, Currency: "USDC", Method: "SUI", Status: int64(models.Paid), ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour))}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = db.Exec(`INSERT INTO community_topups VALUES('deposit','community',1,'0xbb','testnet',?)`, sui.GetCoinType("USDC", "testnet")); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`INSERT INTO community_funding VALUES('run','community','project',1,1,'USDC','testnet')`); err != nil {
				t.Fatal(err)
			}
			if _, err = q.CreateDebugletOrder(t.Context(), database.CreateDebugletOrderParams{TransactionID: "run", OrderID: 1, ExecutorID: "node", Price: 3, Currency: "USDC", State: int64(models.Outstanding)}); err != nil {
				t.Fatal(err)
			}
			h, _ := newEnabledHandler(t, db, enabledConfig(t))
			before, err := h.CommunityBalance(t.Context(), db, "community", "USDC")
			if err != nil || before != (CommunityBudget{Funded: 10, Reserved: 3, Available: 7}) {
				t.Fatalf("prior budget %+v: %v", before, err)
			}
			if _, err = sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), 37); err != nil {
				t.Fatal(err)
			}
			after, err := h.CommunityBalance(t.Context(), db, "community", "USDC")
			if err != nil || after != before {
				t.Fatalf("migrated budget %+v want %+v: %v", after, before, err)
			}
			var currency, network string
			var price int64
			if err = db.QueryRow(`SELECT f.currency,f.network,o.price FROM community_funding f JOIN debuglet_order o ON o.transaction_id=f.transaction_id WHERE f.transaction_id='run'`).Scan(&currency, &network, &price); err != nil || currency != "USDC" || network != "testnet" || price != 3 {
				t.Fatalf("prior funding changed: %s %s %d %v", currency, network, price, err)
			}
			rows, err := db.Query(`PRAGMA foreign_key_check`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			if rows.Next() {
				t.Fatal("foreign key broken during upgrade")
			}
		})
	}
}
