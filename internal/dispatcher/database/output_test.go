// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestOutputMigrationChargesHistoricalLogsWithoutInventingFinality(t *testing.T) {
	ctx, db := cbOpen(t, 9)
	q := database.New(db)
	owned := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	legacy := cbCreate(t, ctx, q, "", "")
	if _, err := db.ExecContext(ctx, `INSERT INTO users(id,uuid,name) VALUES(7,?,'owner')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	// Multiple associations must not multiply a retained frame's charge.
	if _, err := db.ExecContext(ctx, `INSERT INTO debuglet_users(debuglet_id,user_id) VALUES(?,7),(?,7)`, owned.ID, owned.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{owned.ID, legacy.ID} {
		if _, err := db.ExecContext(ctx, `INSERT INTO debuglet_logs(debuglet_id,timestamp,output) VALUES(?,?,?)`, id, models.NewUTCTime(time.Now()), []byte("abc")); err != nil {
			t.Fatal(err)
		}
	}
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), 13); err != nil || version != 13 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	node, err := q.GetOutputNodeUsage(ctx)
	if err != nil || node.ChargedBytes != 134 || node.FrameCount != 2 {
		t.Fatalf("node=%+v err=%v", node, err)
	}
	for _, id := range []int64{0, 7} {
		account, err := q.GetOutputAccountUsage(ctx, id)
		if err != nil || account.ChargedBytes != 67 || account.FrameCount != 1 {
			t.Fatalf("account=%+v err=%v", account, err)
		}
	}
	if _, err := q.GetDebugletOutput(ctx, owned.Uuid); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("historical finality invented: %v", err)
	}
	logs, err := q.ListDebugletLogs(ctx, database.ListDebugletLogsParams{Uuid: owned.Uuid, Limit: 10})
	if err != nil || len(logs) != 1 || logs[0].SourceSequence.Valid {
		t.Fatalf("logs=%+v err=%v", logs, err)
	}
	if err := q.CreateDebugletOutput(ctx, database.CreateDebugletOutputParams{Uuid: owned.Uuid}); err != nil {
		t.Fatal(err)
	}
	meta, err := q.GetDebugletOutput(ctx, owned.Uuid)
	if err != nil || meta.ByteCount != 3 || meta.FrameCount != 1 || meta.LastLogID != logs[0].ID || meta.CommittedSequence != 0 || meta.FinalCursor.Valid || meta.OwnerFingerprint != "" || meta.AccountID != 7 {
		t.Fatalf("legacy metadata=%+v err=%v", meta, err)
	}
}

func TestOutputQueriesCommitPrefixAndFinalityTogether(t *testing.T) {
	ctx, db := cbOpen(t, sqlitedb.Latest)
	q := database.New(db)
	r := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	if err := q.CreateDebugletOutput(ctx, database.CreateDebugletOutputParams{Uuid: r.Uuid, OutputVersion: 1, OwnerFingerprint: "saved-fingerprint"}); err != nil {
		t.Fatal(err)
	}
	if err := q.EnsureOutputAccountUsage(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := q.AddOutputAccountUsage(ctx, database.AddOutputAccountUsageParams{AccountID: 0, Bytes: 256}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddOutputNodeUsage(ctx, database.AddOutputNodeUsageParams{Bytes: 256}); err != nil {
		t.Fatal(err)
	}
	appendInTx := func(commit bool) int64 {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		qt := database.New(tx)
		log, err := qt.CreateSequencedDebugletLog(ctx, database.CreateSequencedDebugletLogParams{DebugletID: r.ID, Timestamp: models.NewUTCTime(time.Unix(1700000000, 123)), Output: []byte("saved"), SourceSequence: sql.NullInt64{Int64: 1, Valid: true}})
		if err != nil {
			t.Fatal(err)
		}
		if changed, err := qt.AdvanceDebugletOutput(ctx, database.AdvanceDebugletOutputParams{Sequence: 1, Bytes: 5, LogID: log.ID, DebugletID: r.ID}); err != nil || changed != 1 {
			t.Fatalf("advance=%d %v", changed, err)
		}
		if err := qt.AddOutputAccountUsage(ctx, database.AddOutputAccountUsageParams{AccountID: 0, Bytes: 69, Frames: 1}); err != nil {
			t.Fatal(err)
		}
		if err := qt.AddOutputNodeUsage(ctx, database.AddOutputNodeUsageParams{Bytes: 69, Frames: 1}); err != nil {
			t.Fatal(err)
		}
		if changed, err := qt.FinishDebugletOutput(ctx, database.FinishDebugletOutputParams{Status: "complete", DebugletID: r.ID, Sequence: 1}); err != nil || changed != 1 {
			t.Fatalf("final=%d %v", changed, err)
		}
		if commit {
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		return log.ID
	}
	appendInTx(false)
	meta, err := q.GetDebugletOutput(ctx, r.Uuid)
	if err != nil || meta.CommittedSequence != 0 || meta.FinalCursor.Valid {
		t.Fatalf("rollback metadata=%+v %v", meta, err)
	}
	node, err := q.GetOutputNodeUsage(ctx)
	if err != nil || node.ChargedBytes != 256 {
		t.Fatalf("rollback usage=%+v %v", node, err)
	}
	last := appendInTx(true)
	meta, err = q.GetDebugletOutput(ctx, r.Uuid)
	if err != nil || meta.CommittedSequence != 1 || meta.FinalCursor.Int64 != last || !meta.FinalCursor.Valid || meta.ByteCount != 5 || meta.FrameCount != 1 || meta.OwnerFingerprint != "saved-fingerprint" || meta.DispatcherIncarnation != cbIncarnation || meta.SessionID != cbSession {
		t.Fatalf("committed=%+v %v", meta, err)
	}
	got, err := q.GetSequencedDebugletLog(ctx, database.GetSequencedDebugletLogParams{DebugletID: r.ID, SourceSequence: sql.NullInt64{Int64: 1, Valid: true}})
	if err != nil || got.ID != last || string(got.Output) != "saved" {
		t.Fatalf("dedupe row=%+v %v", got, err)
	}
	if changed, err := q.FinishDebugletOutput(ctx, database.FinishDebugletOutputParams{Status: "truncated", Reason: "output_limit", DebugletID: r.ID, Sequence: 1}); err != nil || changed != 0 {
		t.Fatalf("final changed=%d %v", changed, err)
	}
	account, err := q.GetOutputAccountUsage(ctx, 0)
	if err != nil || account.ChargedBytes != 325 || account.FrameCount != 1 {
		t.Fatalf("account=%+v %v", account, err)
	}
}
