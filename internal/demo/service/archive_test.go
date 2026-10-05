// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package service

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

func archiveFixture(t *testing.T) (*fixture, string, uuid.UUID) {
	t.Helper()
	f := newFixture(t)
	if _, err := f.install(storagecheck.Executor, "worker", true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(StateDirectory(f.root, storagecheck.Executor, "worker"), "executor.sqlite")
	seedExecutorWork(t, path)
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var id uuid.UUID
	if err := db.QueryRow("SELECT uuid FROM debuglets WHERE started_at IS NULL LIMIT 1").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return f, path, id
}

func TestArchiveRequiresJoinedDrainAndPreservesInspection(t *testing.T) {
	f, path, id := archiveFixture(t)
	ctx := t.Context()
	if _, err := f.installer.ArchiveRun(ctx, "worker", id, "incident-5", true); err == nil {
		t.Fatal("archived a running executor")
	}
	if _, err := f.installer.Drain(ctx, storagecheck.Executor, "worker", DrainOptions{Timeout: time.Second, Disable: true}); err != nil {
		t.Fatal(err)
	}
	dry, err := f.installer.ArchiveRun(ctx, "worker", id, "", false)
	if err != nil || !dry.DryRun || dry.Run.ArchivedAt != nil {
		t.Fatalf("dry=%+v %v", dry, err)
	}
	applied, err := f.installer.ArchiveRun(ctx, "worker", id, "incident-5", true)
	if err != nil || applied.DryRun || applied.Run.ArchivedAt == nil {
		t.Fatalf("apply=%+v %v", applied, err)
	}
	again, err := f.installer.ArchiveRun(ctx, "worker", id, "incident-5", true)
	if err != nil || !reflect.DeepEqual(applied, again) {
		t.Fatalf("retry=%+v %v", again, err)
	}
	d, err := sqlite.InspectDisposition(ctx, path)
	if err != nil || d.Retained != 2 || d.Archived != 1 || d.Quarantined != 1 || d.RetainedTerminal != 2 {
		t.Fatalf("disposition=%+v %v", d, err)
	}
	if _, err := f.installer.Resume(ctx, storagecheck.Executor, "worker"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.installer.ArchiveRun(ctx, "worker", id, "incident-5", true); err == nil {
		t.Fatal("idempotence bypassed shutdown check")
	}
}

type archiveStartRace struct {
	Manager
	calls   int
	startAt int
}

func (m *archiveStartRace) State(ctx context.Context, unit string) (UnitState, error) {
	m.calls++
	if m.calls == m.startAt {
		if err := m.Manager.Start(ctx, unit); err != nil {
			return UnitState{}, err
		}
	}
	return m.Manager.State(ctx, unit)
}

func TestArchiveRefusesChangedServiceAuthority(t *testing.T) {
	for _, scenario := range []string{"failed stop", "still enabled", "changed unit", "changed database", "start during lock"} {
		t.Run(scenario, func(t *testing.T) {
			f, path, id := archiveFixture(t)
			ctx := t.Context()
			if scenario == "failed stop" {
				f.manager.timedOut = true
			}
			_, drainErr := f.installer.Drain(ctx, storagecheck.Executor, "worker", DrainOptions{Timeout: time.Second, Disable: scenario != "still enabled"})
			if scenario != "failed stop" && drainErr != nil {
				t.Fatal(drainErr)
			}
			switch scenario {
			case "changed unit":
				if err := os.WriteFile(filepath.Join(UnitDirectory(f.root), UnitName(storagecheck.Executor, "worker")), []byte("[Service]\nExecStart=/bin/true\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "changed database":
				configPath := filepath.Join(StateDirectory(f.root, storagecheck.Executor, "worker"), "service.toml")
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(configPath, []byte(strings.ReplaceAll(string(data), path, path+"-other")), 0600); err != nil {
					t.Fatal(err)
				}
			case "start during lock":
				// verifyRemoval and checkJoined each query State before acquiring the
				// DB lock; start on the subsequent verification while it is held.
				f.installer.manager = &archiveStartRace{Manager: f.manager, startAt: 3}
			}
			if _, err := f.installer.ArchiveRun(ctx, "worker", id, "incident-6", true); err == nil {
				t.Fatal("accepted unproven shutdown")
			}
			db, err := sqlitedb.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			r, err := sqlite.InspectArchive(ctx, db, id)
			if err != nil || r.ArchivedAt != nil {
				t.Fatalf("refusal changed evidence: %+v %v", r, err)
			}
		})
	}
}

func TestArchiveRefusesDatabaseOwnedByAnotherConnection(t *testing.T) {
	f, path, id := archiveFixture(t)
	ctx := t.Context()
	if _, err := f.installer.Drain(ctx, storagecheck.Executor, "worker", DrainOptions{Timeout: time.Second, Disable: true}); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM debuglets").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if _, err := f.installer.ArchiveRun(ctx, "worker", id, "incident-7", true); err == nil {
		t.Fatal("archived without exclusive database ownership")
	}
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		t.Fatal(err)
	}
	if _, err := f.installer.ArchiveRun(ctx, "worker", id, "incident-7", true); err != nil {
		t.Fatal(err)
	}
}
