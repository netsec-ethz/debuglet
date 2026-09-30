// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package storagecheck

import (
	"context"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestUpgradeRefusesHeldWriter(t *testing.T) {
	for _, mode := range []string{"delete", "wal"} {
		t.Run(mode, func(t *testing.T) {
			path := fixture(t, Executor, 5)
			writer, err := sqlitedb.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if _, err := writer.Exec("PRAGMA journal_mode=" + mode); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Exec("BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			before := digest(t, path)
			_, err = Upgrade(t.Context(), Executor, path)
			if err == nil || !strings.Contains(err.Error(), "exclusive database access") {
				t.Fatalf("held writer upgrade: %v", err)
			}
			if _, err := writer.Exec("ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			unchangedBytes(t, path, before)
			if got := schemaVersionOf(t, path); got != 5 {
				t.Fatalf("refused upgrade advanced schema to %d", got)
			}
			if _, err := Upgrade(t.Context(), Executor, path); err != nil {
				t.Fatalf("upgrade after writer closes: %v", err)
			}
		})
	}
}

func TestUpgradeOwnsDatabaseAcrossCommits(t *testing.T) {
	for _, mode := range []string{"delete", "wal"} {
		t.Run(mode, func(t *testing.T) {
			path := fixture(t, Executor, 5)
			modify(t, path, "PRAGMA journal_mode="+mode)
			owner, err := openUpgrade(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			other, err := sqlitedb.Open(path, sqlitedb.BusyTimeout(0))
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			for i := 0; i < 2; i++ {
				if _, err := owner.Exec("BEGIN"); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec("COMMIT"); err != nil {
					t.Fatal(err)
				}
				if _, err := other.Exec("BEGIN IMMEDIATE"); err == nil {
					other.Exec("ROLLBACK")
					t.Fatal("other writer acquired the database between migration commits")
				}
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := other.Exec("BEGIN IMMEDIATE"); err != nil {
				t.Fatalf("writer after ownership release: %v", err)
			}
			if _, err := other.Exec("ROLLBACK"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUpgradePreservesPreviousPopulatedSchemas(t *testing.T) {
	dispatcher := populated[0]
	dispatcher.name, dispatcher.version = "dispatcher version 12", 12
	dispatcher.rows = append(append([]string{}, dispatcher.rows...),
		"INSERT INTO debuglet_provenance (debuglet_id, document) VALUES (1, '{\"version\":\"1.1\"}')",
		"INSERT INTO debuglet_cancellations (debuglet_id, request_id, reason, requested_at) VALUES (1, 'cancel1', 'user', 1767225600000000000)",
		"INSERT INTO debuglet_output (debuglet_id, output_version, owner_fingerprint, account_id, committed_sequence, byte_count, frame_count, last_log_id, final_sequence, final_cursor, status) VALUES (1, 1, 'fp', 1, 1, 2, 1, 1, 1, 1, 'complete')")
	executor := populated[len(populated)-1]
	executor.name, executor.version = "executor version 5", 5
	executor.rows = append(append([]string{}, executor.rows...),
		"INSERT INTO tesla_chains (generation, anchor, epoch_base, delay_ns, chain_length, created_at) VALUES (1, x'010203', '2026-01-01 00:00:00', 10000000000, 1000, '2026-01-01 00:00:00')")
	for _, fixture := range []populatedDatabase{dispatcher, executor} {
		t.Run(fixture.name, func(t *testing.T) {
			path := fixture.fixture(t)
			if _, err := Upgrade(context.Background(), fixture.role, path); err != nil {
				t.Fatal(err)
			}
			if err := Check(t.Context(), fixture.role, path); err != nil {
				t.Fatalf("upgraded state rejected by current package policy: %v", err)
			}
			for _, query := range []string{
				"SELECT COUNT(*) FROM debuglets WHERE id=1 AND session_id='session'",
				"SELECT COUNT(*) FROM debuglet_logs WHERE output=x'6869'",
			} {
				if got := count(t, path, query); got != 1 {
					t.Fatalf("preserved run/binding/output: %q = %d", query, got)
				}
			}
			if fixture.role == Dispatcher {
				for _, table := range []string{"debuglet_provenance", "debuglet_cancellations", "debuglet_output"} {
					if got := count(t, path, "SELECT COUNT(*) FROM "+table+" WHERE debuglet_id=1"); got != 1 {
						t.Fatalf("retained %s records=%d", table, got)
					}
				}
			} else if got := count(t, path, "SELECT COUNT(*) FROM tesla_chains WHERE generation=1 AND anchor=x'010203' AND chain_length=1000"); got != 1 {
				t.Fatalf("historical chain descriptors=%d", got)
			}
		})
	}
}
