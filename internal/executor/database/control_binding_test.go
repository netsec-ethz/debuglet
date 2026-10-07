package database_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
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

func TestControlBindingMigrationPreservesExecutorRows(t *testing.T) {
	ctx, db := cbOpen(t, 2)
	now := database.NewUTCTime(time.Now())
	wasm := []byte("retained WASM fixture")
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	for i, id := range ids {
		started := database.UTCTime{}
		if i == 1 {
			started = now
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO debuglets (uuid,start_time,args,wasm,transaction_id,floor_bw,ceil_bw,timeout_ms,addresses,require_icmp,listen_udp,listen_tcp,listen_scion,started_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, now, database.CommaSeparatedList{"retained-argument"}, wasm, "legacy-transaction", 12, 34, 5000, database.CommaSeparatedList{"127.0.0.1"}, true, false, true, false, started); err != nil {
			t.Fatal(err)
		}
	}
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), 3); err != nil || version != 3 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	for _, id := range ids {
		var incarnation, session string
		if err := db.QueryRowContext(ctx, "SELECT dispatcher_incarnation, session_id FROM debuglets WHERE uuid = ?", id).Scan(&incarnation, &session); err != nil || incarnation != "" || session != "" {
			t.Fatalf("schema 3 assigned legacy ownership: incarnation=%q session=%q err=%v", incarnation, session, err)
		}
	}
	// Keep the historical boundary above separate from current query coverage.
	if _, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	q := database.New(db)
	rows, err := q.ListDebuglets(ctx, database.ListDebugletsParams{Limit: 10})
	if err != nil || len(rows) != 2 {
		t.Fatalf("legacy inspection rows=%d err=%v", len(rows), err)
	}
	for i, id := range ids {
		row, err := q.GetDebugletByUUID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if row.DispatcherIncarnation != "" || row.SessionID != "" || !bytes.Equal(row.Wasm, wasm) || row.TransactionID != "legacy-transaction" || row.FloorBw != 12 || row.CeilBw != 34 || row.TimeoutMs != 5000 || !reflect.DeepEqual(row.Args, database.CommaSeparatedList{"retained-argument"}) || !reflect.DeepEqual(row.Addresses, database.CommaSeparatedList{"127.0.0.1"}) || !row.StartTime.Equal(now.Time) || !row.RequireIcmp || row.ListenUdp || !row.ListenTcp || row.ListenScion {
			t.Fatalf("migration changed legacy spec: %+v", row)
		}
		if (i == 0 && !row.StartedAt.IsZero()) || (i == 1 && !row.StartedAt.Equal(now.Time)) {
			t.Fatalf("migration changed start marker: %+v", row)
		}
		if len(row.EgressGrant) != 0 {
			t.Fatalf("migration granted legacy traffic authority: %x", row.EgressGrant)
		}
		if _, err := q.GetOwnedDebugletByUUID(ctx, database.GetOwnedDebugletByUUIDParams{Uuid: id}); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("legacy row acquired an empty owner: %v", err)
		}
		got, err := q.GetDebugletByUUID(ctx, id)
		if err != nil || !reflect.DeepEqual(got, row) {
			t.Fatalf("rejected ownership changed legacy row: %+v err=%v", got, err)
		}
	}
	// These queries preserve inspectable rows. Actual exclusion from scheduler
	// emission belongs to the runtime restore-policy integration, not this test.
}

func TestControlBindingExecutorOwnedQueries(t *testing.T) {
	ctx, db := cbOpen(t, sqlitedb.Latest)
	q := database.New(db)
	id := uuid.New()
	input := database.CreateDebugletParams{Uuid: id, Wasm: []byte("bound WASM"), TransactionID: "bound-transaction", FloorBw: 12, CeilBw: 34, TimeoutMs: 1000, DispatcherIncarnation: cbIncarnation, SessionID: cbSession}
	if err := q.CreateDebuglet(ctx, input); err != nil {
		t.Fatal(err)
	}
	owner := database.GetOwnedDebugletByUUIDParams{Uuid: id, DispatcherIncarnation: cbIncarnation, SessionID: cbSession}
	row, err := q.GetOwnedDebugletByUUID(ctx, owner)
	if err != nil || row.DispatcherIncarnation != input.DispatcherIncarnation || row.SessionID != input.SessionID || !bytes.Equal(row.Wasm, input.Wasm) {
		t.Fatalf("owned persisted roundtrip=%+v err=%v", row, err)
	}
	for _, name := range []string{"incarnation", "session", "missing_uuid"} {
		t.Run(name, func(t *testing.T) {
			wrong := owner
			switch name {
			case "incarnation":
				wrong.DispatcherIncarnation = uuid.NewString()
			case "session":
				wrong.SessionID = uuid.NewString()
			case "missing_uuid":
				wrong.Uuid = uuid.New()
			}
			if _, err := q.GetOwnedDebugletByUUID(ctx, wrong); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("wrong run owner returned %v", err)
			}
		})
	}
	started := database.NewUTCTime(time.Now())
	updated, err := q.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{Uuid: id, StartedAt: started})
	if err != nil || updated.DispatcherIncarnation != row.DispatcherIncarnation || updated.SessionID != row.SessionID || !updated.StartedAt.Equal(started.Time) {
		t.Fatalf("start marker changed immutable binding: %+v err=%v", updated, err)
	}
	for _, tc := range []struct{ name, incarnation, session string }{
		{"empty_incarnation", "", cbSession}, {"empty_session", cbIncarnation, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			incomplete := input
			incomplete.Uuid = uuid.New()
			incomplete.DispatcherIncarnation, incomplete.SessionID = tc.incarnation, tc.session
			if err := q.CreateDebuglet(ctx, incomplete); err != nil {
				t.Fatal(err)
			}
			if _, err := q.GetOwnedDebugletByUUID(ctx, database.GetOwnedDebugletByUUIDParams{Uuid: incomplete.Uuid, DispatcherIncarnation: tc.incarnation, SessionID: tc.session}); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("incomplete stored binding accepted: %v", err)
			}
		})
	}
	rows, err := q.ListDebuglets(ctx, database.ListDebugletsParams{Limit: 10})
	if err != nil || len(rows) != 3 {
		t.Fatalf("binding inspection lost rows: count=%d err=%v", len(rows), err)
	}
	if got, err := q.GetOwnedDebugletByUUID(ctx, owner); err != nil || !reflect.DeepEqual(got, updated) {
		t.Fatalf("other ownership attempts changed bound run: got=%+v want=%+v err=%v", got, updated, err)
	}
}
