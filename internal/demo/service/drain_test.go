package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	_ "modernc.org/sqlite"
)

// seedExecutorWork writes the three kinds of retained state a drained executor
// can hold: work that was accepted but never started, work that was started,
// and terminal results that were never acknowledged.
func seedExecutorWork(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open executor database: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close executor database: %v", err)
		}
	}()
	queries := database.New(db)
	ctx := context.Background()
	binding := struct{ incarnation, session string }{"incarnation-a", "session-a"}
	started := uuid.New()
	for i, id := range []uuid.UUID{uuid.New(), started} {
		incarnation, session := binding.incarnation, binding.session
		if i == 0 {
			// A second control session leaves its own retained rows.
			incarnation, session = "incarnation-b", "session-b"
		}
		if err := queries.CreateDebuglet(ctx, database.CreateDebugletParams{
			Uuid: id, StartTime: database.NewUTCTime(time.Now()), Args: []string{"a"},
			Wasm: []byte{0x00, 0x61, 0x73, 0x6d}, TransactionID: fmt.Sprintf("tx-%d", i),
			FloorBw: 1000, CeilBw: 2000, TimeoutMs: 1000, Addresses: []string{"127.0.0.1"},
			DispatcherIncarnation: incarnation, SessionID: session,
		}); err != nil {
			t.Fatalf("seed debuglet: %v", err)
		}
	}
	if _, err := queries.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{
		Uuid: started, StartedAt: database.NewUTCTime(time.Now()),
	}); err != nil {
		t.Fatalf("seed start marker: %v", err)
	}
	for i := 0; i < 2; i++ {
		id := uuid.New().String()
		if err := queries.RecordDebugletExit(ctx, database.RecordDebugletExitParams{
			DebugletID: id, DispatcherIncarnation: binding.incarnation, SessionID: binding.session,
			ExitCode: int64(i), RecordedAt: database.NewUTCTime(time.Now()),
		}); err != nil {
			t.Fatalf("seed terminal result: %v", err)
		}
		if i == 1 {
			// One result was actually sent and permanently refused; the
			// other never left the executor at all.
			if _, err := queries.NoteDebugletExitFailure(ctx, database.NoteDebugletExitFailureParams{
				Attempts: 2, LastAttemptAt: database.NewUTCTime(time.Now()), LastError: "refused",
				Rejected: true, DebugletID: id, DispatcherIncarnation: binding.incarnation, SessionID: binding.session,
			}); err != nil {
				t.Fatalf("seed delivery failure: %v", err)
			}
		}
	}
}

func TestDrainExecutorJoinsAndReportsDisposition(t *testing.T) {
	f := newFixture(t)
	if _, err := f.install(demo.DispatcherSchema, "local", true); err != nil {
		t.Fatalf("install dispatcher: %v", err)
	}
	if _, err := f.install(demo.ExecutorSchema, "worker", true); err != nil {
		t.Fatalf("install executor: %v", err)
	}
	if _, err := f.install(demo.ExecutorSchema, "other", true); err != nil {
		t.Fatalf("install second executor: %v", err)
	}
	drained := StateDirectory(f.root, demo.ExecutorSchema, "worker")
	seedExecutorWork(t, filepath.Join(drained, "executor.sqlite"))

	report, err := f.installer.Drain(context.Background(), demo.ExecutorSchema, "worker",
		DrainOptions{Timeout: 2 * time.Second, Disable: true})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if !report.Joined || report.Outcome != "drained" || report.Enabled {
		t.Fatalf("drain report: %+v", report)
	}
	if report.Disposition == nil {
		t.Fatalf("a joined drain reported no disposition: %+v", report)
	}
	d := *report.Disposition
	if d.Retained != 2 || d.Queued != 1 || d.Started != 1 || d.Quarantined != 2 || d.Bindings != 2 {
		t.Fatalf("retained execution rows: %+v", d)
	}
	if d.RetainedTerminal != 2 || d.UnsentTerminal != 1 || d.RejectedTerminal != 1 {
		t.Fatalf("retained terminal results: %+v", d)
	}
	if d.Empty() {
		t.Fatalf("a node holding retained work reported nothing to preserve: %+v", d)
	}

	// Nothing was deleted or replayed: the same rows are still there.
	again, err := f.installer.Drain(context.Background(), demo.ExecutorSchema, "worker",
		DrainOptions{Timeout: 2 * time.Second, Disable: true})
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if again.Disposition == nil || *again.Disposition != d {
		t.Fatalf("draining again altered retained work: %+v", again.Disposition)
	}

	// Every other managed role keeps serving.
	for _, unit := range []string{UnitName(demo.DispatcherSchema, "local"), UnitName(demo.ExecutorSchema, "other")} {
		state, err := f.manager.State(context.Background(), unit)
		if err != nil {
			t.Fatal(err)
		}
		if !state.Running() || !state.Enabled {
			t.Fatalf("draining one executor disturbed %s: %+v", unit, state)
		}
	}
	other := filepath.Join(StateDirectory(f.root, demo.ExecutorSchema, "other"), "executor.sqlite")
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("the unrelated executor lost its database: %v", err)
	}

	// Resuming serves again without replaying anything.
	resumed, err := f.installer.Resume(context.Background(), demo.ExecutorSchema, "worker")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.Outcome != "started" || !resumed.Ready || !resumed.Enabled {
		t.Fatalf("resume report: %+v", resumed)
	}
}

func TestDrainWithoutAJoinAuthorizesNothing(t *testing.T) {
	t.Run("a unit that never stops is incomplete", func(t *testing.T) {
		f := newFixture(t)
		if _, err := f.install(demo.ExecutorSchema, "worker", true); err != nil {
			t.Fatalf("install: %v", err)
		}
		f.manager.stuck = true
		report, err := f.installer.Drain(context.Background(), demo.ExecutorSchema, "worker",
			DrainOptions{Timeout: 500 * time.Millisecond, Disable: true})
		if !errors.Is(err, ErrDrainIncomplete) {
			t.Fatalf("drain error: %v", err)
		}
		if report.Joined || report.Outcome != "incomplete" || report.Disposition != nil {
			t.Fatalf("incomplete drain report: %+v", report)
		}
		if report.Note == "" {
			t.Fatal("an incomplete drain has to say what it does not authorize")
		}
		// It is still eligible to come back: an unfinished drain decides
		// nothing, so it does not disable the unit either.
		if !report.Enabled {
			t.Fatalf("an unfinished drain disabled the unit: %+v", report)
		}
		if _, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", true); err == nil {
			t.Fatal("state was deleted after an unfinished drain")
		}
		if _, err := os.Stat(filepath.Join(StateDirectory(f.root, demo.ExecutorSchema, "worker"), "executor.sqlite")); err != nil {
			t.Fatalf("an unfinished drain lost the database: %v", err)
		}
	})
	t.Run("a daemon killed at its stop timeout is incomplete", func(t *testing.T) {
		f := newFixture(t)
		if _, err := f.install(demo.ExecutorSchema, "worker", true); err != nil {
			t.Fatalf("install: %v", err)
		}
		f.manager.timedOut = true
		report, err := f.installer.Drain(context.Background(), demo.ExecutorSchema, "worker",
			DrainOptions{Timeout: time.Second, Disable: true})
		if !errors.Is(err, ErrDrainIncomplete) {
			t.Fatalf("drain error: %v", err)
		}
		if report.Joined || report.Disposition != nil || report.Outcome != "incomplete" {
			t.Fatalf("incomplete drain report: %+v", report)
		}
		// The unit is down and its readiness record is gone with its
		// runtime directory, and neither of those is a join.
		if report.Active != "failed" {
			t.Fatalf("expected a failed unit: %+v", report)
		}
		if _, err := os.Stat(f.readyFile(demo.ExecutorSchema, "worker")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("runtime directory outlived the stop: %v", err)
		}
		if _, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", true); err == nil {
			t.Fatal("state was deleted after a drain that never joined")
		}
	})
}

func TestDispatcherAdmissionStopAndResume(t *testing.T) {
	f := newFixture(t)
	if _, err := f.install(demo.DispatcherSchema, "local", true); err != nil {
		t.Fatalf("install: %v", err)
	}
	unit := UnitName(demo.DispatcherSchema, "local")
	mark := len(f.manager.recorded())
	report, err := f.installer.Drain(context.Background(), demo.DispatcherSchema, "local",
		DrainOptions{Reason: "planned\nmaintenance", Timeout: time.Second})
	if err != nil {
		t.Fatalf("drain dispatcher: %v", err)
	}
	if report.Outcome != "paused" || report.Joined {
		t.Fatalf("dispatcher drain report: %+v", report)
	}
	// The dispatcher keeps serving: stopping admission is not stopping it.
	for _, call := range f.manager.recorded()[mark:] {
		if call == "stop "+unit || call == "disable "+unit {
			t.Fatalf("draining a dispatcher %q", call)
		}
	}
	if !report.Ready || report.Active != "active" {
		t.Fatalf("the dispatcher stopped serving: %+v", report)
	}
	switchPath := filepath.Join(AdministrationDirectory(f.root), "dispatcher-local.maintenance")
	state, err := ReadMaintenance(switchPath)
	if err != nil || !state.Paused {
		t.Fatalf("maintenance switch: %+v %v", state, err)
	}
	if state.Reason != "planned maintenance" || state.SchemaVersion != maintenanceSchema {
		t.Fatalf("maintenance record: %+v", state)
	}
	// The dispatcher may read the switch and may not remove it, so it
	// cannot take itself out of maintenance.
	if strings.HasPrefix(switchPath, StateDirectory(f.root, demo.DispatcherSchema, "local")) {
		t.Fatalf("the switch is inside the account's own directory: %s", switchPath)
	}
	if _, owned := f.chowned[switchPath]; owned {
		t.Fatalf("the switch was handed to the service account")
	}
	if info, err := os.Lstat(switchPath); err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("maintenance switch mode: %v %v", info, err)
	}
	if status, err := f.installer.Status(context.Background(), demo.DispatcherSchema, "local"); err != nil || status.Note == "" {
		t.Fatalf("status does not report maintenance: %+v %v", status, err)
	}
	resumed, err := f.installer.Resume(context.Background(), demo.DispatcherSchema, "local")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.Outcome != "resumed" || !slicesContains(resumed.Changed, "maintenance switch") {
		t.Fatalf("resume report: %+v", resumed)
	}
	if _, err := os.Stat(switchPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the maintenance switch survived the resume: %v", err)
	}
	// Resuming twice is not an error and changes nothing.
	if second, err := f.installer.Resume(context.Background(), demo.DispatcherSchema, "local"); err != nil || len(second.Changed) != 0 {
		t.Fatalf("repeated resume: %+v %v", second, err)
	}
}

// The switch file carries the operator's note, and the dispatcher repeats it in
// its refusal, so the note is bounded in bytes here too. The bound must fall on
// a character boundary: a record holding half a rune would be repeated into a
// JSON body that is not valid UTF-8.
func TestAMaintenanceNoteIsRecordedOnARuneBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance")
	for name, note := range map[string]string{
		"two-byte runes":      strings.Repeat("ä", 300),
		"four-byte runes":     strings.Repeat("🛠", 300),
		"a rune on the bound": strings.Repeat("a", reasonLimit-1) + "ä",
	} {
		t.Run(name, func(t *testing.T) {
			if err := WriteMaintenance(path, note, time.Now()); err != nil {
				t.Fatal(err)
			}
			record, err := ReadMaintenance(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(record.Reason) > reasonLimit {
				t.Fatalf("a note of %d bytes was recorded as %d", len(note), len(record.Reason))
			}
			if !utf8.ValidString(record.Reason) {
				t.Fatalf("the recorded note is not valid UTF-8: %q", record.Reason)
			}
			if record.Reason == "" {
				t.Fatal("the whole note was dropped")
			}
		})
	}
}
