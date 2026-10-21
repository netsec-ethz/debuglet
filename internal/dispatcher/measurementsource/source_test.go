// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package measurementsource

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestSaveAtAccountLimitKeepsExistingSourceAndRejectsNewAttachment(t *testing.T) {
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "source.sqlite"), sqlitedb.Create(), sqlitedb.WithoutSync())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	owner := uuid.New()
	exec("INSERT INTO users(uuid,name) VALUES (?, 'Owner')", owner)
	exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1024)
 INSERT INTO transactions(id,auth_key,price,method,expires_at,hash,currency,status)
 SELECT 'source-'||i,'unused',0,'TEST',CURRENT_TIMESTAMP,'','TEST',1 FROM n`)
	first := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	second := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	next := uuid.New()
	digest := strings.Repeat("a", 64)
	for _, run := range []struct {
		id          uuid.UUID
		measurement string
	}{{first, "source-0"}, {second, "source-0"}, {next, "source-1024"}} {
		exec(`INSERT INTO debuglets(uuid,start_time,end_time,usage,ceil_bw,executor_id,state,transaction_id)
 VALUES (?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,0,0,'executor',0,?)`, run.id, run.measurement)
		exec(`INSERT INTO debuglet_users(debuglet_id,user_id) SELECT d.id,u.id FROM debuglets d,users u WHERE d.uuid=? AND u.uuid=?`, run.id, owner)
		exec(`INSERT INTO debuglet_provenance(debuglet_id,document) SELECT id,json_object('workload_sha256',?) FROM debuglets WHERE uuid=?`, digest, run.id)
	}
	input := Input{
		Kind:     "workflow",
		Document: []byte(`{"version":1,"name":"Saved","entry":"wait","nodes":[{"id":"wait","block":"wait","inputs":{"duration_ms":1}}],"edges":[]}`),
		Programs: []wire.SourceProgram{{RunID: second.String(), SHA256: digest}, {RunID: first.String(), SHA256: digest}},
	}
	store := Store{DB: db}
	saved, created, err := store.Save(t.Context(), owner, "source-0", input)
	if err != nil || !created {
		t.Fatalf("first save: created=%v error=%v", created, err)
	}
	if input.Programs[0].RunID != second.String() || saved.Programs[0].RunID != first.String() {
		t.Fatal("canonicalization mutated the caller's input or failed to sort stored programs")
	}
	exec(`INSERT INTO measurement_sources(measurement_id,user_id,kind,document,document_sha256,programs)
 SELECT t.id,u.id,'workflow','{}',?,'[]' FROM transactions t,users u WHERE t.id NOT IN ('source-0','source-1024') AND u.uuid=?`, digest, owner)
	repeated, created, err := store.Save(t.Context(), owner, "source-0", input)
	if err != nil || created || repeated.DocumentSHA256 != saved.DocumentSHA256 {
		t.Fatalf("idempotent save at quota: created=%v error=%v", created, err)
	}
	input.Programs = []wire.SourceProgram{{RunID: next.String(), SHA256: digest}}
	_, _, err = store.Save(t.Context(), owner, "source-1024", input)
	var invalid *ValidationError
	if !errors.As(err, &invalid) || !invalid.Conflict {
		t.Fatalf("new attachment at quota: %v", err)
	}
	var count int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM measurement_sources").Scan(&count); err != nil || count != 1024 {
		t.Fatalf("failed attachment changed retained source count: %d, %v", count, err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	retained, err := Read(t.Context(), tx, first, owner)
	if err != nil || retained.DocumentSHA256 != saved.DocumentSHA256 {
		t.Fatalf("original source after quota rejection: %v", err)
	}
}
