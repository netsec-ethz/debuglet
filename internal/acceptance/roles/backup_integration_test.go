// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && roles_integration

package roles

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/demo"
	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestInstalledBackupRestore(t *testing.T) {
	root := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute installed package directory is required")
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatalf("installed/source identity: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	work := t.TempDir()
	if err := os.Chmod(work, 0700); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) []byte {
		t.Helper()
		out, diagnostics, err := runCommand(ctx, assets.CLI, work, isolatedEnvironment(work),
			append([]string{"--config", filepath.Join(work, "client.json"), "--output", "json"}, args...)...)
		if err != nil {
			t.Fatalf("CLI %s: %v; stdout=%q stderr=%q", args[0], err, out, diagnostics)
		}
		return out
	}
	start := func(kind, state, endpoint string) *role {
		t.Helper()
		args := []string{"--config", filepath.Join(work, kind+".json"), "--output", "json", kind, "up", "--name", kind, "--state-dir", state}
		if kind == "dispatcher" {
			args = append(args, "--port", "0", "--grpc-port", "0")
		} else {
			args = append(args, "--dispatcher", endpoint)
		}
		r, err := startRole(assets, work, kind, kind, state, args)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if !r.stopped {
				if err := r.stop(); err != nil {
					t.Error("role cleanup:", err)
				}
			}
		})
		phase, done := context.WithTimeout(ctx, 20*time.Second)
		defer done()
		if err := r.ready(phase); err != nil {
			_, diagnostics, _ := r.output.snapshot()
			t.Fatalf("%s startup: %v; stderr=%q", kind, err, diagnostics)
		}
		return r
	}
	stop := func(r *role) {
		t.Helper()
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}
	}
	submit := func(argument string) uuid.UUID {
		t.Helper()
		var receipt struct {
			ID            string `json:"id"`
			TransactionID string `json:"transaction_id"`
			ExecutorID    string `json:"executor_id"`
			State         string `json:"state"`
			Error         string `json:"error"`
		}
		if err := decode(cli("run", "--sample", "hello", "--wait", "--", argument), &receipt); err != nil || !validID(receipt.ID) || receipt.State != client.StateExited || receipt.Error != "" {
			t.Fatalf("unsuccessful run: %+v, %v", receipt, err)
		}
		return uuid.MustParse(receipt.ID)
	}

	d := start("dispatcher", filepath.Join(work, "original-dispatcher"), "")
	cli("connect", d.record.Endpoint, "--name", "recovery")
	e := start("executor", filepath.Join(work, "original-executor"), d.record.Endpoint)
	first := submit("before-backup")
	awaitOutput(t, ctx, sdk(t, d.record.Endpoint), first.String(), hello+"before-backup\n")
	stop(e)
	stop(d)
	oldBinding := storedBinding(t, d.state, first)
	wasm, err := os.ReadFile(filepath.Join(root, "share", "debuglet", "hello.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	retained := seedRetained(t, e.state, oldBinding, wasm)
	assertRetained(t, e.state, retained)

	restored := make(map[string]string)
	for _, original := range []*role{d, e} {
		backup := filepath.Join(work, original.kind+"-backup")
		state := filepath.Join(work, "restored-"+original.kind)
		var manifest demo.BackupManifest
		if err := decode(cli("backup", "--state-dir", original.state, "--destination", backup, "--offline"), &manifest); err != nil || manifest.Package.SourceSHA != assets.Manifest.SourceSHA {
			t.Fatalf("backup manifest: %+v, %v", manifest, err)
		}
		cli("restore", "--backup", backup, "--state-dir", state)
		before, err := os.ReadFile(filepath.Join(original.state, "role-state.json"))
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(filepath.Join(state, "role-state.json"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("restored %s identity changed: %v", original.kind, err)
		}
		restored[original.kind] = state
	}
	assertRetained(t, restored["executor"], retained)
	recoveryStart := time.Now()
	d2 := start("dispatcher", restored["dispatcher"], "")
	cli("connect", d2.record.Endpoint, "--name", "recovery")
	e2 := start("executor", restored["executor"], d2.record.Endpoint)
	if e2.record.ExecutorID != e.record.ExecutorID {
		t.Fatal("restore changed executor identity")
	}
	c := sdk(t, d2.record.Endpoint)
	assertStatus(t, ctx, c, first.String(), e2.record.ExecutorID)
	awaitOutput(t, ctx, c, first.String(), hello+"before-backup\n")
	last := submit("after-restore")
	awaitOutput(t, ctx, c, last.String(), hello+"after-restore\n")
	recoveryElapsed := time.Since(recoveryStart)
	stop(e2)
	stop(d2)
	newBinding := storedBinding(t, d2.state, last)
	if newBinding.Incarnation == oldBinding.Incarnation || newBinding.SessionID == oldBinding.SessionID {
		t.Fatalf("fresh measurement reused the old control binding: old=%+v new=%+v", oldBinding, newBinding)
	}
	// Read after joined shutdown: old runnable WASM, start markers and terminal
	// result must survive both restored startup and a completed fresh measurement.
	assertRetained(t, e2.state, retained)
	assertRetained(t, e.state, retained)
	if storedBinding(t, d.state, first) != oldBinding || storedBinding(t, d2.state, first) != oldBinding {
		t.Fatal("retained completed measurement changed binding")
	}
	t.Logf("installed backup/restore retained identities, completed output and queued/started/terminal rows; new control binding completed fresh TEST in %s", recoveryElapsed)
}

func backupDB(t *testing.T, state string, role storagecheck.Role) *sql.DB {
	t.Helper()
	db, err := sqlitedb.Open(demo.RoleDatabase(state, role))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func storedBinding(t *testing.T, state string, id uuid.UUID) controlsession.Binding {
	t.Helper()
	db := backupDB(t, state, storagecheck.Dispatcher)
	defer db.Close()
	row, err := dispatcherdb.New(db).GetDebugletIdentityByUUID(t.Context(), id)
	binding := controlsession.Binding{Incarnation: row.DispatcherIncarnation, SessionID: row.SessionID}
	if err != nil || !binding.Valid() {
		t.Fatalf("stored control binding: %+v, %v", row, err)
	}
	return binding
}

type retainedFixture struct {
	runs     []executordb.Debuglet
	terminal executordb.DebugletExit
	chains   []executordb.TeslaChain
}

func seedRetained(t *testing.T, state string, binding controlsession.Binding, wasm []byte) retainedFixture {
	t.Helper()
	db := backupDB(t, state, storagecheck.Executor)
	defer db.Close()
	q := executordb.New(db)
	fixture := retainedFixture{}
	now := executordb.NewUTCTime(time.Now().Add(-time.Second))
	for _, started := range []bool{false, true} {
		id := uuid.New()
		if err := q.CreateDebuglet(t.Context(), executordb.CreateDebugletParams{Uuid: id, StartTime: now, Wasm: wasm, TransactionID: "TEST", FloorBw: 1, CeilBw: 10, TimeoutMs: 120000, DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID}); err != nil {
			t.Fatal(err)
		}
		if started {
			// Seed the historical schema before the candidate upgrades it;
			// current ownership queries require the current schema.
			if _, err := db.ExecContext(t.Context(), "UPDATE debuglets SET started_at=? WHERE uuid=?", now, id); err != nil {
				t.Fatal(err)
			}
		}
		row, err := q.GetDebugletByUUID(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		fixture.runs = append(fixture.runs, row)
	}
	id := uuid.New().String()
	if _, err := db.ExecContext(t.Context(), "INSERT INTO debuglet_exits(debuglet_id,dispatcher_incarnation,session_id,exit_code,recorded_at) VALUES(?,?,?,?,?)", id, binding.Incarnation, binding.SessionID, 0, now); err != nil {
		t.Fatal(err)
	}
	var err error
	fixture.terminal, err = q.GetDebugletExit(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	fixture.chains, err = q.ListTeslaChains(t.Context())
	if err != nil || len(fixture.chains) == 0 {
		t.Fatalf("original schedule history: %v", err)
	}
	return fixture
}

func assertRetained(t *testing.T, state string, fixture retainedFixture) {
	t.Helper()
	db := backupDB(t, state, storagecheck.Executor)
	defer db.Close()
	q := executordb.New(db)
	for _, before := range fixture.runs {
		after, err := q.GetDebugletByUUID(t.Context(), before.Uuid)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("retained run changed or replayed: %s: %v", before.Uuid, err)
		}
		var logs, exits int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM debuglet_logs WHERE debuglet_id=?", before.ID).Scan(&logs); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM debuglet_exits WHERE debuglet_id=?", before.Uuid.String()).Scan(&exits); err != nil || logs != 0 || exits != 0 {
			t.Fatalf("retained run produced output/exit: %d/%d, %v", logs, exits, err)
		}
	}
	after, err := q.GetDebugletExit(t.Context(), fixture.terminal.DebugletID)
	if err != nil || !reflect.DeepEqual(fixture.terminal, after) {
		t.Fatalf("retained terminal changed or retried: %+v, %v", after, err)
	}
	chains, err := q.ListTeslaChains(t.Context())
	if err != nil || len(chains) < len(fixture.chains) || !reflect.DeepEqual(fixture.chains, chains[:len(fixture.chains)]) {
		t.Fatalf("retained schedule history changed: %v", err)
	}
}
