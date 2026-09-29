package database_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

const (
	cbIncarnation = "c31f0dc2-3f96-4a5a-aa2a-a4bcc16d88fb"
	cbSession     = "6f2f15d8-f982-44a8-b22c-8d80fa5f8b62"
)

func cbOpen(t *testing.T, version int64) (context.Context, *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "binding.sqlite"), sqlitedb.Create(), sqlitedb.WithoutSync())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), version); err != nil {
		t.Fatal(err)
	}
	return ctx, db
}

func cbCreate(t *testing.T, ctx context.Context, q *database.Queries, incarnation, session string) database.Debuglet {
	t.Helper()
	now := models.NewUTCTime(time.Now())
	row, err := q.CreateDebuglet(ctx, database.CreateDebugletParams{
		Uuid: uuid.New(), StartTime: now, EndTime: models.NewUTCTime(now.Add(time.Minute)),
		Usage: 123, CeilBw: 456, ExecutorID: "binding-executor", Addresses: models.CommaSeparatedList{"127.0.0.1"},
		State: models.RunStateUploaded, TransactionID: "binding-transaction", OrderID: 7,
		DispatcherIncarnation: incarnation, SessionID: session,
	})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func cbOwner(row database.Debuglet) database.GetOwnedDebugletByUUIDParams {
	return database.GetOwnedDebugletByUUIDParams{Uuid: row.Uuid, ExecutorID: row.ExecutorID, DispatcherIncarnation: row.DispatcherIncarnation, SessionID: row.SessionID}
}

// Each rejected operation executes its real SQL statement. The final snapshot
// and log count prove rejection did not silently mutate or insert a row.
func cbReject(t *testing.T, ctx context.Context, q *database.Queries, row database.Debuglet, owner database.GetOwnedDebugletByUUIDParams) {
	t.Helper()
	assertNoRows := func(operation string, err error) {
		t.Helper()
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("%s: got %v, want sql.ErrNoRows", operation, err)
		}
	}
	_, err := q.GetOwnedDebugletByUUID(ctx, owner)
	assertNoRows("owned lookup", err)
	_, err = q.UpdateDebugletState(ctx, database.UpdateDebugletStateParams{Uuid: owner.Uuid, ExecutorID: owner.ExecutorID, DispatcherIncarnation: owner.DispatcherIncarnation, SessionID: owner.SessionID, State: models.RunStateStarted, StateRank: models.RunStateStarted.SemanticRank(), ExitedState: models.RunStateExited})
	assertNoRows("ordinary state", err)
	_, err = q.CompleteDebuglet(ctx, database.CompleteDebugletParams{Uuid: owner.Uuid, ExecutorID: owner.ExecutorID, DispatcherIncarnation: owner.DispatcherIncarnation, SessionID: owner.SessionID, ExitedState: models.RunStateExited, Error: sql.NullString{String: "must not persist", Valid: true}})
	assertNoRows("terminal result", err)
	before, err := q.ListDebugletLogs(ctx, database.ListDebugletLogsParams{Uuid: row.Uuid, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.CreateDebugletLog(ctx, database.CreateDebugletLogParams{Uuid: owner.Uuid, ExecutorID: owner.ExecutorID, DispatcherIncarnation: owner.DispatcherIncarnation, SessionID: owner.SessionID, Timestamp: models.NewUTCTime(time.Now()), Output: []byte("must not insert")})
	assertNoRows("output frame", err)
	after, err := q.ListDebugletLogs(ctx, database.ListDebugletLogsParams{Uuid: row.Uuid, Limit: 10})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected output changed logs: before=%v after=%v err=%v", before, after, err)
	}
	got, err := q.GetDebugletByUUID(ctx, row.Uuid)
	if err != nil || !reflect.DeepEqual(got, row) {
		t.Fatalf("rejected owner changed run: got=%+v want=%+v err=%v", got, row, err)
	}
}

func TestControlBindingMigrationPreservesDispatcherRows(t *testing.T) {
	ctx, db := cbOpen(t, 4)
	id := uuid.New()
	now := models.NewUTCTime(time.Now())
	var legacyID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO debuglets (uuid,start_time,end_time,usage,ceil_bw,executor_id,addresses,state,error,transaction_id,order_id) VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING id`, id, now, now, 12, 34, "legacy-executor", "127.0.0.1", models.RunStateUploaded, "preserved error", "legacy-transaction", 9).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO debuglet_logs (debuglet_id,timestamp,output) VALUES (?,?,?)`, legacyID, now, []byte("preserved output")); err != nil {
		t.Fatal(err)
	}
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), sqlitedb.Latest); err != nil || version != 13 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	q := database.New(db)
	row, err := q.GetDebugletByUUID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != legacyID || row.DispatcherIncarnation != "" || row.SessionID != "" || row.Usage != 12 || row.CeilBw != 34 || row.State != models.RunStateUploaded || row.Error != (sql.NullString{String: "preserved error", Valid: true}) || row.TransactionID != "legacy-transaction" || row.OrderID != 9 {
		t.Fatalf("migration changed legacy run: %+v", row)
	}
	logs, err := q.ListDebugletLogs(ctx, database.ListDebugletLogsParams{Uuid: id, Limit: 10})
	if err != nil || len(logs) != 1 || string(logs[0].Output) != "preserved output" || logs[0].DebugletID != legacyID {
		t.Fatalf("migration changed legacy output: logs=%+v err=%v", logs, err)
	}
	cbReject(t, ctx, q, row, cbOwner(row))
}

func TestControlBindingDispatcherOwnedQueries(t *testing.T) {
	ctx, db := cbOpen(t, sqlitedb.Latest)
	q := database.New(db)
	row := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	owner := cbOwner(row)
	if got, err := q.GetOwnedDebugletByUUID(ctx, owner); err != nil || !reflect.DeepEqual(got, row) {
		t.Fatalf("owned roundtrip=%+v err=%v", got, err)
	}
	for _, name := range []string{"executor", "incarnation", "session", "missing_uuid"} {
		t.Run(name, func(t *testing.T) {
			wrong := owner
			switch name {
			case "executor":
				wrong.ExecutorID = "another-executor"
			case "incarnation":
				wrong.DispatcherIncarnation = uuid.NewString()
			case "session":
				wrong.SessionID = uuid.NewString()
			case "missing_uuid":
				wrong.Uuid = uuid.New()
			}
			cbReject(t, ctx, q, row, wrong)
		})
	}
	updated, err := q.UpdateDebugletState(ctx, database.UpdateDebugletStateParams{Uuid: owner.Uuid, ExecutorID: owner.ExecutorID, DispatcherIncarnation: owner.DispatcherIncarnation, SessionID: owner.SessionID, State: models.RunStateStarted, StateRank: models.RunStateStarted.SemanticRank(), ExitedState: models.RunStateExited})
	if err != nil || updated.State != models.RunStateStarted || cbOwner(updated) != owner {
		t.Fatalf("owned ordinary update=%+v err=%v", updated, err)
	}
	winnerError := sql.NullString{String: "  exact terminal result\n", Valid: true}
	terminal := database.CompleteDebugletParams{Uuid: owner.Uuid, ExecutorID: owner.ExecutorID, DispatcherIncarnation: owner.DispatcherIncarnation, SessionID: owner.SessionID, ExitedState: models.RunStateExited, Error: winnerError}
	winner, err := q.CompleteDebuglet(ctx, terminal)
	if err != nil || winner.State != models.RunStateExited || winner.Error != winnerError || cbOwner(winner) != owner {
		t.Fatalf("owned terminal update=%+v err=%v", winner, err)
	}
	terminal.Error = sql.NullString{}
	if _, err := q.CompleteDebuglet(ctx, terminal); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("duplicate terminal result: %v", err)
	}
	if _, err := q.UpdateDebugletState(ctx, database.UpdateDebugletStateParams{Uuid: owner.Uuid, ExecutorID: owner.ExecutorID, DispatcherIncarnation: owner.DispatcherIncarnation, SessionID: owner.SessionID, State: models.RunStateStarted, StateRank: models.RunStateStarted.SemanticRank(), ExitedState: models.RunStateExited}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("late ordinary result: %v", err)
	}
	// Terminal reporting can precede the output pump. Session fencing must not
	// silently impose output finality, which remains a separate contract.
	log, err := q.CreateDebugletLog(ctx, database.CreateDebugletLogParams{Uuid: owner.Uuid, ExecutorID: owner.ExecutorID, DispatcherIncarnation: owner.DispatcherIncarnation, SessionID: owner.SessionID, Timestamp: models.NewUTCTime(time.Now()), Output: []byte("trailing authorized output")})
	if err != nil || log.DebugletID != row.ID || string(log.Output) != "trailing authorized output" {
		t.Fatalf("authorized post-terminal output=%+v err=%v", log, err)
	}
	if got, err := q.GetDebugletByUUID(ctx, row.Uuid); err != nil || !reflect.DeepEqual(got, winner) {
		t.Fatalf("winner changed: got=%+v want=%+v err=%v", got, winner, err)
	}
}

func TestControlBindingDispatcherRejectsEmptyStoredComponents(t *testing.T) {
	for _, tc := range []struct{ name, incarnation, session string }{
		{"empty_incarnation", "", cbSession}, {"empty_session", cbIncarnation, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db := cbOpen(t, sqlitedb.Latest)
			q := database.New(db)
			row := cbCreate(t, ctx, q, tc.incarnation, tc.session)
			cbReject(t, ctx, q, row, cbOwner(row))
		})
	}
}
