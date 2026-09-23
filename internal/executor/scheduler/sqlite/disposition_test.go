package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
)

// A drained node with nothing retained has to say so plainly: an operator
// decides whether state may be discarded from this answer.
func TestInspectDispositionOfEmptyStorage(t *testing.T) {
	path := newBootstrappedDatabase(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := InspectDisposition(context.Background(), path)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !d.Empty() || d.Retained != 0 || d.Bindings != 0 || d.RetainedTerminal != 0 || d.Truncated {
		t.Fatalf("empty storage reported %+v", d)
	}
	if d.Summary() == "" {
		t.Fatal("a disposition without a summary cannot be reported to an operator")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the inspection changed the database it read")
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm", path + "-journal"} {
		if _, err := os.Lstat(sidecar); err == nil {
			t.Fatalf("the inspection created %s", filepath.Base(sidecar))
		}
	}
}

func TestInspectDispositionRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	if _, err := InspectDisposition(context.Background(), filepath.Join(dir, "absent.sqlite")); err == nil {
		t.Fatal("an absent database was inspected")
	}
	if _, err := InspectDisposition(context.Background(), dir); err == nil {
		t.Fatal("a directory was inspected as a database")
	}
	if _, err := InspectDisposition(context.Background(), ""); err == nil {
		t.Fatal("an empty path was inspected")
	}
}

// seedRetainedRuns writes one retained row per control session, and marks the
// first row of each as started.
func seedRetainedRunsAt(t *testing.T, path string, sessions, perSession int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()
	seedRetainedRuns(t, db, sessions, perSession)
}

func seedRetainedRuns(t *testing.T, db *sql.DB, sessions, perSession int) {
	t.Helper()
	queries := database.New(db)
	ctx := context.Background()
	for session := 0; session < sessions; session++ {
		for row := 0; row < perSession; row++ {
			id := uuid.New()
			if err := queries.CreateDebuglet(ctx, database.CreateDebugletParams{
				Uuid: id, StartTime: database.NewUTCTime(time.Now()), Wasm: []byte{0x00, 0x61, 0x73, 0x6d},
				TransactionID: fmt.Sprintf("tx-%d-%d", session, row), FloorBw: 1, CeilBw: 2, TimeoutMs: 1,
				DispatcherIncarnation: fmt.Sprintf("incarnation-%02d", session),
				SessionID:             fmt.Sprintf("session-%02d", session),
			}); err != nil {
				t.Fatalf("seed run: %v", err)
			}
			if row == 0 {
				if _, err := queries.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{
					Uuid: id, StartedAt: database.NewUTCTime(time.Now()),
				}); err != nil {
					t.Fatalf("seed start marker: %v", err)
				}
			}
		}
	}
}

// Rows and results are counted exactly however many there are; only the number
// of control sessions they came from is bounded, and reaching that bound is
// reported instead of silently dropping the rest.
func TestInspectDispositionCountsRowsExactlyAndBoundsSessions(t *testing.T) {
	path := newBootstrappedDatabase(t)
	seedRetainedRunsAt(t, path, 3, 2)
	full, err := InspectDisposition(context.Background(), path)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if full.Retained != 6 || full.Started != 3 || full.Queued != 3 || full.Quarantined != 6 {
		t.Fatalf("counts: %+v", full)
	}
	if full.Bindings != 3 || full.Truncated {
		t.Fatalf("sessions: %+v", full)
	}

	previous := dispositionBindingLimit
	dispositionBindingLimit = 2
	t.Cleanup(func() { dispositionBindingLimit = previous })
	bounded, err := InspectDisposition(context.Background(), path)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if bounded.Retained != full.Retained || bounded.Started != full.Started || bounded.Quarantined != full.Quarantined {
		t.Fatalf("the row counts changed with the session bound: %+v", bounded)
	}
	if bounded.Bindings != 2 || !bounded.Truncated {
		t.Fatalf("the session bound was not reported: %+v", bounded)
	}
	if !strings.Contains(bounded.Summary(), "at least 2 control sessions") {
		t.Fatalf("summary: %s", bounded.Summary())
	}
}

// A killed daemon leaves its write-ahead log behind, and that is exactly when
// an operator needs to know what the node still holds. Both shapes a kill can
// leave are read here: the log alone, and the log together with the shared
// memory file whose contents no live process backs any more.
func TestInspectDispositionReadsADatabaseLeftWithAWriteAheadLog(t *testing.T) {
	path := newBootstrappedDatabase(t)
	live, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	live.SetMaxOpenConns(1)
	var mode string
	if err := live.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("enable the write-ahead log: %q %v", mode, err)
	}
	// The same connection writes, so the log is still the writer's when
	// the files below are copied.
	seedRetainedRuns(t, live, 1, 2)
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("no write-ahead log to leave behind: %v %v", info, err)
	}
	for name, sidecars := range map[string][]string{
		"log":                   {"-wal"},
		"log and shared memory": {"-wal", "-shm"},
	} {
		t.Run(name, func(t *testing.T) {
			// Copy the files as they are while the writer still holds
			// them: that is what a process killed now leaves on disk.
			killed := filepath.Join(t.TempDir(), "executor.sqlite")
			for _, suffix := range append([]string{""}, sidecars...) {
				data, err := os.ReadFile(path + suffix)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(killed+suffix, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(killed)
			if err != nil {
				t.Fatal(err)
			}
			d, err := InspectDisposition(context.Background(), killed)
			if err != nil {
				t.Fatalf("inspect a database left with a write-ahead log: %v", err)
			}
			// The committed rows are in the log, so a reader that
			// ignored it would report an empty node.
			if d.Retained != 2 || d.Started != 1 || d.Queued != 1 {
				t.Fatalf("the counts of a recovered database are wrong: %+v", d)
			}
			// The database itself is untouched, and no file the
			// killed writer did not leave is left behind, except
			// the shared-memory index SQLite builds to read the
			// log: that one belongs to the database's own owner,
			// not to the administrator who ran the command.
			after, err := os.ReadFile(killed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("the inspection changed the database it read")
			}
			for _, suffix := range []string{"-wal", "-journal"} {
				if slices.Contains(sidecars, suffix) {
					continue
				}
				if _, err := os.Lstat(killed + suffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the inspection left %s behind: %v", suffix, err)
				}
			}
			if index, err := os.Lstat(killed + "-shm"); err == nil {
				owner, err := os.Stat(killed)
				if err != nil {
					t.Fatal(err)
				}
				wantUID, wantGID, ok := fileOwner(owner)
				gotUID, gotGID, alsoOK := fileOwner(index)
				if !ok || !alsoOK || gotUID != wantUID || gotGID != wantGID {
					t.Fatalf("the index left behind belongs to %d:%d, the database to %d:%d", gotUID, gotGID, wantUID, wantGID)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		})
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
}

// The shared-memory index an inspection builds must not be left belonging to
// the administrator who ran the command: the daemon could not write it at its
// next start. It is handed to the database's own owner rather than removed,
// because a daemon started since the read may already be serving on it. The
// account owns that directory, so nothing but the index itself is accepted:
// not a link, not a second name for a file elsewhere, and not a named pipe,
// which would otherwise make the drain wait for somebody to answer it.
func TestTheSharedMemoryIndexIsHandedToTheDatabasesOwner(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "executor.sqlite")
	if err := os.WriteFile(database, []byte("database"), 0600); err != nil {
		t.Fatal(err)
	}
	owner, err := os.Stat(database)
	if err != nil {
		t.Fatal(err)
	}
	index := database + "-shm"
	if err := os.WriteFile(index, []byte("index"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ownLike(owner, index); err != nil {
		t.Fatalf("hand the index over: %v", err)
	}
	handed, err := os.Stat(index)
	if err != nil {
		t.Fatalf("the index was removed instead of handed over: %v", err)
	}
	wantUID, wantGID, ok := fileOwner(owner)
	gotUID, gotGID, alsoOK := fileOwner(handed)
	if !ok || !alsoOK || gotUID != wantUID || gotGID != wantGID {
		t.Fatalf("the index belongs to %d:%d, the database to %d:%d", gotUID, gotGID, wantUID, wantGID)
	}

	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(elsewhere, []byte("host file"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, plant := range map[string]func(t *testing.T){
		"a link in its place":                 func(t *testing.T) { mustSymlink(t, elsewhere, index) },
		"a second name for a host file":       func(t *testing.T) { mustLink(t, elsewhere, index) },
		"a pipe with nobody at the other end": func(t *testing.T) { mustPipe(t, index) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.Remove(index); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			plant(t)
			done := make(chan error, 1)
			go func() { done <- ownLike(owner, index) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("the planted entry was handed over")
				}
			case <-time.After(20 * time.Second):
				t.Fatal("the handover is waiting on the planted entry")
			}
			if _, err := os.Lstat(elsewhere); err != nil {
				t.Fatalf("the file behind the planted entry was touched: %v", err)
			}
		})
	}
}

// An index that is already gone, because SQLite removed it when the last
// connection closed, is nothing to hand over.
func TestAnAbsentSharedMemoryIndexIsNothingToHandOver(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "executor.sqlite")
	if err := os.WriteFile(database, []byte("database"), 0600); err != nil {
		t.Fatal(err)
	}
	owner, err := os.Stat(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := ownLike(owner, database+"-shm"); err != nil {
		t.Fatalf("an index that is not there: %v", err)
	}
}
