// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package storagecheck

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// These are real packaged schemas, not files with a changed version marker.
// Startup must refuse them before any of the newly compiled queries can run.
func TestDispatcherRolloutRequiresExplicitUpgrade(t *testing.T) {
	for _, version := range []int64{35, 36, 37} {
		t.Run(strconv.FormatInt(version, 10), func(t *testing.T) {
			path := fixture(t, Dispatcher, version)
			before := digest(t, path)
			if err := Check(t.Context(), Dispatcher, path); !errors.Is(err, ErrOutdated) {
				t.Fatalf("schema %d check: %v", version, err)
			}
			db, err := OpenForService(t.Context(), Dispatcher, path)
			if db != nil {
				db.Close()
				t.Fatal("old schema opened for service")
			}
			if !errors.Is(err, ErrOutdated) {
				t.Fatalf("schema %d startup: %v", version, err)
			}
			unchanged(t, path, before)
			if got, err := Upgrade(t.Context(), Dispatcher, path); err != nil || got != 38 {
				t.Fatalf("upgrade schema %d: version=%d err=%v", version, got, err)
			}
			db, err = OpenForService(t.Context(), Dispatcher, path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			for _, table := range rolloutTables {
				var count int
				if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
					t.Fatalf("query %s after upgrade: %v", table, err)
				}
			}
		})
	}
}

var rolloutTables = []string{"allowance_eligibility", "hosting_approvals", "allowance_periods", "prepaid_topups", "personal_funding", "hosting_awards", "native_gas_reservations", "assistant_keys"}

func TestDispatcherRolloutDetectsIncompleteCurrentSchema(t *testing.T) {
	path := fixture(t, Dispatcher, 0)
	for _, table := range rolloutTables {
		t.Run(table, func(t *testing.T) {
			modify(t, path, "ALTER TABLE "+table+" RENAME TO incomplete_table")
			before := digest(t, path)
			err := Check(t.Context(), Dispatcher, path)
			if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), table) {
				t.Fatalf("missing %s accepted: %v", table, err)
			}
			unchanged(t, path, before)
			modify(t, path, "ALTER TABLE incomplete_table RENAME TO "+table)
		})
	}
	// A table name alone does not establish that the migration finished.
	modify(t, path, "ALTER TABLE assistant_keys RENAME COLUMN encrypted_key TO incomplete_column")
	before := digest(t, path)
	err := Check(t.Context(), Dispatcher, path)
	if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), "encrypted_key") {
		t.Fatalf("missing key column accepted: %v", err)
	}
	unchanged(t, path, before)
}
