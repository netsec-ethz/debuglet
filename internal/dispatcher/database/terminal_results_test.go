package database_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"

	"github.com/google/uuid"

	_ "modernc.org/sqlite"
)

const (
	trIncarnation   = "00000000-0000-4000-8000-000000000001"
	trSession       = "00000000-0000-4000-8000-000000000002"
	trBusyTimeoutMS = 5000
	trMigrationsDir = "migrations"
	trRaceBound     = 15 * time.Second
	trFailureText   = "debuglet exited with code 7"
	trVerbatimText  = "  verbatim: quotes ' \" and\nnewline, unicode ü  "
)

// The generated parameter types preserve the result contract: every
// exited_state binds models.RunStateExited directly, error is sql.NullString
// and uuid is uuid.UUID. These assignments fail to compile on a mismatch.
var (
	_ models.DebugletRunState = database.CompleteDebugletParams{}.ExitedState
	_ sql.NullString          = database.CompleteDebugletParams{}.Error
	_ uuid.UUID               = database.CompleteDebugletParams{}.Uuid
	_ models.DebugletRunState = database.UpdateDebugletStateParams{}.State
	_ models.DebugletRunState = database.UpdateDebugletStateParams{}.ExitedState
	_ uuid.UUID               = database.UpdateDebugletStateParams{}.Uuid
	_ database.Debuglet
)

var (
	trSuccess = sql.NullString{}
	trFailure = sql.NullString{String: trFailureText, Valid: true}
)

// trOpen opens one *sql.DB handle to path with a single pooled connection and
// a bounded busy timeout, and proves the timeout is in effect on that
// connection: without it, a concurrent writer would surface SQLITE_BUSY.
// synchronous(OFF) only skips fsync; locking and journaling, which decide the
// winner, are unchanged. On the CI container's overlay filesystem fsync
// otherwise costs about half a second per fixture.
func trOpen(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=synchronous(OFF)", path, trBusyTimeoutMS))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close sqlite: %v", err)
		}
	})
	var timeout int
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if timeout != trBusyTimeoutMS {
		t.Fatalf("busy_timeout is %d, want %d", timeout, trBusyTimeoutMS)
	}
	return db
}

// trFresh creates a fresh migrated database file with one nonterminal
// debuglet row and returns the path and that row's uuid.
func trFresh(t *testing.T) (string, uuid.UUID) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "terminal.sqlite")
	db := trOpen(t, path)
	testutil.ApplyMigrations(t, db, trMigrationsDir)
	id := uuid.New()
	now := time.Now()
	row, err := database.New(db).CreateDebuglet(context.Background(), database.CreateDebugletParams{
		DispatcherIncarnation: trIncarnation, SessionID: trSession,
		Uuid:          id,
		StartTime:     models.NewUTCTime(now),
		EndTime:       models.NewUTCTime(now.Add(time.Minute)),
		Usage:         1000,
		CeilBw:        2000,
		ExecutorID:    "tr-executor",
		Addresses:     models.CommaSeparatedList{"127.0.0.1"},
		State:         models.RunStateUploaded,
		TransactionID: "tr-tx",
		OrderID:       1,
	})
	if err != nil {
		t.Fatalf("create debuglet: %v", err)
	}
	if row.State != models.RunStateUploaded || row.Error.Valid {
		t.Fatalf("fresh row is %+v, want Uploaded with NULL error", row)
	}
	return path, id
}

func trComplete(ctx context.Context, db *sql.DB, id uuid.UUID, result sql.NullString) (database.Debuglet, error) {
	return database.New(db).CompleteDebuglet(ctx, database.CompleteDebugletParams{
		ExecutorID: "tr-executor", DispatcherIncarnation: trIncarnation, SessionID: trSession, ExitedState: models.RunStateExited,
		Error: result,
		Uuid:  id,
	})
}

func trGet(t *testing.T, db *sql.DB, id uuid.UUID) database.Debuglet {
	t.Helper()
	row, err := database.New(db).GetDebugletByUUID(context.Background(), id)
	if err != nil {
		t.Fatalf("get debuglet: %v", err)
	}
	return row
}

// trAssertTerminal checks that the observed row is Exited with exactly the
// winner's error (NULL stays NULL, text is stored verbatim).
func trAssertTerminal(t *testing.T, row database.Debuglet, winner sql.NullString) {
	t.Helper()
	if row.State != models.RunStateExited {
		t.Fatalf("row state is %s, want RunStateExited", row.State)
	}
	if row.Error != winner {
		t.Fatalf("row error is %+v, want the winner's %+v", row.Error, winner)
	}
}

// TestCompleteDebugletAtomic proves CompleteDebuglet is the single atomic
// terminal writer: under concurrent success/failure attempts from two
// separate connections exactly one returns the row and the other
// sql.ErrNoRows, and the stored state and error belong to that winner. Any
// other error, including SQLITE_BUSY, fails the test.
func TestCompleteDebugletAtomic(t *testing.T) {
	t.Run("concurrent success and failure yield one winner", func(t *testing.T) {
		path, id := trFresh(t)
		dbA := trOpen(t, path)
		dbB := trOpen(t, path)

		ctx, cancel := context.WithTimeout(context.Background(), trRaceBound)
		defer cancel()

		type attempt struct {
			db     *sql.DB
			result sql.NullString
			row    database.Debuglet
			err    error
		}
		attempts := []*attempt{{db: dbA, result: trSuccess}, {db: dbB, result: trFailure}}

		start := make(chan struct{})
		done := make(chan struct{})
		var wg sync.WaitGroup
		for _, a := range attempts {
			wg.Add(1)
			go func(a *attempt) {
				defer wg.Done()
				<-start
				a.row, a.err = trComplete(ctx, a.db, id, a.result)
			}(a)
		}
		go func() {
			wg.Wait()
			close(done)
		}()
		close(start)
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatalf("concurrent CompleteDebuglet did not finish within %s", trRaceBound)
		}

		var winners, losers []*attempt
		for _, a := range attempts {
			switch {
			case a.err == nil:
				winners = append(winners, a)
			case errors.Is(a.err, sql.ErrNoRows):
				losers = append(losers, a)
			default:
				t.Fatalf("CompleteDebuglet with error=%+v returned %v; only sql.ErrNoRows is an accepted loser", a.result, a.err)
			}
		}
		if len(winners) != 1 || len(losers) != 1 {
			t.Fatalf("got %d winners and %d losers, want exactly one of each", len(winners), len(losers))
		}
		winner := winners[0]
		trAssertTerminal(t, winner.row, winner.result)
		if winner.row.Uuid != id {
			t.Fatalf("winner row uuid %s, want %s", winner.row.Uuid, id)
		}
		trAssertTerminal(t, trGet(t, dbA, id), winner.result)
		trAssertTerminal(t, trGet(t, dbB, id), winner.result)
	})

	orders := []struct {
		name          string
		first, second sql.NullString
	}{
		{"sequential success then failure keeps success", trSuccess, trFailure},
		{"sequential failure then success keeps failure", trFailure, trSuccess},
	}
	for _, tc := range orders {
		t.Run(tc.name, func(t *testing.T) {
			path, id := trFresh(t)
			db := trOpen(t, path)
			ctx := context.Background()

			row, err := trComplete(ctx, db, id, tc.first)
			if err != nil {
				t.Fatalf("first CompleteDebuglet: %v", err)
			}
			trAssertTerminal(t, row, tc.first)

			if _, err := trComplete(ctx, db, id, tc.second); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("second CompleteDebuglet returned %v, want sql.ErrNoRows", err)
			}
			trAssertTerminal(t, trGet(t, db, id), tc.first)
		})
	}

	t.Run("late ordinary state after completion is rejected and leaves the row", func(t *testing.T) {
		path, id := trFresh(t)
		db := trOpen(t, path)
		ctx := context.Background()
		q := database.New(db)

		if _, err := trComplete(ctx, db, id, trFailure); err != nil {
			t.Fatalf("CompleteDebuglet: %v", err)
		}
		for _, late := range []models.DebugletRunState{models.RunStateStarted, models.RunStateUploaded, models.RunStateInitializing} {
			if _, err := q.UpdateDebugletState(ctx, database.UpdateDebugletStateParams{
				ExecutorID: "tr-executor", DispatcherIncarnation: trIncarnation, SessionID: trSession, State: late, StateRank: late.SemanticRank(),
				Uuid:        id,
				ExitedState: models.RunStateExited,
			}); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("UpdateDebugletState(%s) after completion returned %v, want sql.ErrNoRows", late, err)
			}
			trAssertTerminal(t, trGet(t, db, id), trFailure)
		}
	})

	t.Run("ordinary state before completion still updates", func(t *testing.T) {
		path, id := trFresh(t)
		db := trOpen(t, path)
		row, err := database.New(db).UpdateDebugletState(context.Background(), database.UpdateDebugletStateParams{
			ExecutorID: "tr-executor", DispatcherIncarnation: trIncarnation, SessionID: trSession, State: models.RunStateStarted, StateRank: models.RunStateStarted.SemanticRank(),
			Uuid:        id,
			ExitedState: models.RunStateExited,
		})
		if err != nil {
			t.Fatalf("UpdateDebugletState on a nonterminal row: %v", err)
		}
		if row.State != models.RunStateStarted || row.Error.Valid {
			t.Fatalf("row after ordinary update is %+v, want Started with NULL error", row)
		}
	})

	t.Run("missing uuid yields ErrNoRows for both queries", func(t *testing.T) {
		path, _ := trFresh(t)
		db := trOpen(t, path)
		ctx := context.Background()
		missing := uuid.New()

		if _, err := trComplete(ctx, db, missing, trFailure); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("CompleteDebuglet on a missing uuid returned %v, want sql.ErrNoRows", err)
		}
		if _, err := database.New(db).UpdateDebugletState(ctx, database.UpdateDebugletStateParams{
			ExecutorID: "tr-executor", DispatcherIncarnation: trIncarnation, SessionID: trSession, State: models.RunStateStarted, StateRank: models.RunStateStarted.SemanticRank(),
			Uuid:        missing,
			ExitedState: models.RunStateExited,
		}); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("UpdateDebugletState on a missing uuid returned %v, want sql.ErrNoRows", err)
		}
	})

	t.Run("nullable error preservation", func(t *testing.T) {
		t.Run("NULL winner stays NULL", func(t *testing.T) {
			path, id := trFresh(t)
			db := trOpen(t, path)
			ctx := context.Background()
			if _, err := trComplete(ctx, db, id, trSuccess); err != nil {
				t.Fatalf("CompleteDebuglet: %v", err)
			}
			if _, err := trComplete(ctx, db, id, trFailure); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("duplicate returned %v, want sql.ErrNoRows", err)
			}
			var raw sql.NullString
			if err := db.QueryRow("SELECT error FROM debuglets WHERE uuid = ?", id).Scan(&raw); err != nil {
				t.Fatalf("read error column: %v", err)
			}
			if raw.Valid {
				t.Fatalf("error column is %q, want SQL NULL", raw.String)
			}
		})
		t.Run("text winner is stored verbatim", func(t *testing.T) {
			path, id := trFresh(t)
			db := trOpen(t, path)
			verbatim := sql.NullString{String: trVerbatimText, Valid: true}
			row, err := trComplete(context.Background(), db, id, verbatim)
			if err != nil {
				t.Fatalf("CompleteDebuglet: %v", err)
			}
			trAssertTerminal(t, row, verbatim)
			var raw sql.NullString
			if err := db.QueryRow("SELECT error FROM debuglets WHERE uuid = ?", id).Scan(&raw); err != nil {
				t.Fatalf("read error column: %v", err)
			}
			if raw != verbatim {
				t.Fatalf("error column is %+v, want %+v", raw, verbatim)
			}
		})
		t.Run("empty string is distinct from NULL", func(t *testing.T) {
			path, id := trFresh(t)
			db := trOpen(t, path)
			empty := sql.NullString{String: "", Valid: true}
			row, err := trComplete(context.Background(), db, id, empty)
			if err != nil {
				t.Fatalf("CompleteDebuglet: %v", err)
			}
			trAssertTerminal(t, row, empty)
			trAssertTerminal(t, trGet(t, db, id), empty)
		})
	})
}
