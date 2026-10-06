// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// Schema 24 starts the status history from the TESLA chains already on
// record and keeps every existing row; enrolled executors that never
// registered get no status row and read as never connected.
func TestProbeStatusMigrationBackfillsFromRecordedChains(t *testing.T) {
	ctx, db := cbOpen(t, 23)
	const second = int64(1_000_000_000)
	for _, chain := range []struct {
		executor, chain string
		first, last     int64
	}{
		{"old-executor", "a", 1_700_000_000, 1_700_000_100},
		{"old-executor", "b", 1_700_100_000, 1_700_200_000},
		{"single-chain", "c", 1_750_000_000, 1_750_000_000},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO attribution_chains (executor_id, chain_id, anchor, t0_ns, interval_ns, delay_epochs, chain_length, tag_spec, first_seen_ns, last_seen_ns)
			VALUES (?, ?, x'01', 0, 1, 2, 10, 1, ?, ?)`, chain.executor, chain.chain, chain.first*second+5, chain.last*second+7); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, uuid, name) VALUES (3, ?, 'owner')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO owned_executors (executor_id, user_id, name, created_at) VALUES ('enrolled-only', 3, 'lab', CURRENT_TIMESTAMP), ('old-executor', 3, 'old', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), 24); err != nil || version != 24 {
		t.Fatalf("migration=%d, %v", version, err)
	}
	q := database.New(db)
	rows, err := q.ListProbeStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []database.ProbeStatus{
		{ExecutorID: "old-executor", FirstConnected: 1_700_000_000, LastConnected: 1_700_200_000, StatusSince: 1_700_200_000, IsPublic: 1},
		{ExecutorID: "single-chain", FirstConnected: 1_750_000_000, LastConnected: 1_750_000_000, StatusSince: 1_750_000_000, IsPublic: 1},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("backfill = %+v, want %+v", rows, want)
	}
	var chains int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM attribution_chains`).Scan(&chains); err != nil || chains != 3 {
		t.Fatalf("chains = %d, %v", chains, err)
	}
	enrolled, err := q.ListEnrolledExecutorIDs(ctx)
	if err != nil || !reflect.DeepEqual(enrolled, []string{"enrolled-only", "old-executor"}) {
		t.Fatalf("enrolled = %v, %v", enrolled, err)
	}
}

func TestProbeStatusStreaksAndAddressRuns(t *testing.T) {
	ctx, db := cbOpen(t, sqlitedb.Latest)
	q := database.New(db)
	connect := func(now int64) {
		t.Helper()
		if err := q.RecordProbeConnected(ctx, database.RecordProbeConnectedParams{ExecutorID: "e", Now: now, IsPublic: 1, HostTags: "home,fibre", Version: "v1"}); err != nil {
			t.Fatal(err)
		}
	}
	row := func() database.ProbeStatus {
		t.Helper()
		rows, err := q.ListProbeStatus(ctx)
		if err != nil || len(rows) != 1 {
			t.Fatalf("rows = %+v, %v", rows, err)
		}
		return rows[0]
	}
	touch := func(now int64) int64 {
		t.Helper()
		n, err := q.TouchProbeConnected(ctx, database.TouchProbeConnectedParams{Now: now, ExecutorID: "e"})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	connect(1000)
	if r := row(); r.FirstConnected != 1000 || r.StatusSince != 1000 || r.Connected != 1 || r.TotalUptime != 0 || r.HostTags != "home,fibre" {
		t.Fatalf("first registration: %+v", r)
	}
	if touch(1060) != 1 || touch(1120) != 1 || touch(1100) != 0 {
		t.Fatal("touch did not advance monotonically")
	}
	// A replacement session within the grace continues the streak.
	connect(1200)
	if r := row(); r.StatusSince != 1000 || r.TotalUptime != 200 || r.LastConnected != 1200 {
		t.Fatalf("replacement: %+v", r)
	}
	// A dispatcher that stopped left the row connected; a registration long
	// after starts a new streak and counts nothing in between.
	connect(5000)
	if r := row(); r.StatusSince != 5000 || r.TotalUptime != 200 || r.FirstConnected != 1000 {
		t.Fatalf("stale connected row: %+v", r)
	}
	if n, err := q.RecordProbeDisconnected(ctx, "e"); err != nil || n != 1 {
		t.Fatalf("disconnect: %d %v", n, err)
	}
	if r := row(); r.Connected != 0 || r.StatusSince != 5000 || touch(6000) != 0 {
		t.Fatalf("disconnected: %+v", r)
	}
	connect(6000)
	if r := row(); r.Connected != 1 || r.StatusSince != 6000 || r.TotalUptime != 200 {
		t.Fatalf("reconnect: %+v", r)
	}

	observe := func(family int64, address string, at int64) {
		t.Helper()
		n, err := q.ExtendProbeAddress(ctx, database.ExtendProbeAddressParams{At: at, ExecutorID: "e", Family: family, Address: address})
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			if _, err := q.StartProbeAddress(ctx, database.StartProbeAddressParams{ExecutorID: "e", Family: family, Address: address, Via: "control", At: at}); err != nil {
				t.Fatal(err)
			}
		}
	}
	observe(4, "192.0.2.1", 100)
	observe(4, "192.0.2.1", 200)
	observe(4, "192.0.2.2", 300)
	observe(4, "192.0.2.1", 250) // Older than the newest run: never reopens a run.
	observe(4, "192.0.2.1", 400)
	observe(6, "2001:db8::1", 150)
	latest, err := q.ListLatestProbeAddresses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 || latest[0].Address != "192.0.2.1" || latest[0].FirstObserved != 400 || latest[1].Address != "2001:db8::1" || latest[1].LastObserved != 150 {
		t.Fatalf("latest runs: %+v", latest)
	}
	if n, err := q.PruneProbeAddresses(ctx, 1000); err != nil || n != 2 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	var runs int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM probe_addresses`).Scan(&runs); err != nil || runs != 2 {
		t.Fatalf("pruning removed a latest run: %d %v", runs, err)
	}
}
