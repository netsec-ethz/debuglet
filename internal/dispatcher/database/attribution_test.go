// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package database_test

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestAttributionMigrationKeepsRunsAndStartsTheHistoryNow(t *testing.T) {
	ctx, db := cbOpen(t, 13)
	q := database.New(db)
	run := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	before := time.Now().Add(-time.Second)
	if version, err := sqlitedb.Migrate(ctx, db, database.MigrationFS(), sqlitedb.Latest); err != nil || version != 14 {
		t.Fatalf("migration=%d, %v", version, err)
	}
	got, err := q.GetDebugletByUUID(ctx, run.Uuid)
	if err != nil || !reflect.DeepEqual(got, run) {
		t.Fatalf("migration changed run: %+v, %v", got, err)
	}
	// History recorded before the upgrade does not exist, so it starts now.
	retained, err := q.GetAttributionRetention(ctx)
	if err != nil || retained < before.Truncate(time.Second).UnixNano() || retained > time.Now().UnixNano() {
		t.Fatalf("retained_from=%d, %v; want the migration time", retained, err)
	}
	rows, err := q.ListAttributionCandidates(ctx, database.ListAttributionCandidatesParams{SourceIp: "127.0.0.1", AtNs: time.Now().UnixNano(), MaxRows: 33})
	if err != nil || len(rows) != 0 {
		t.Fatalf("migration invented attribution runs: %v, %v", rows, err)
	}
}

func TestAttributionHistoryRecordsChainsKeysAndRuns(t *testing.T) {
	ctx, db := cbOpen(t, 14)
	q := database.New(db)
	const executor, chain = "binding-executor", "c1"
	t0 := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	interval := time.Minute
	record := func(seen time.Time) {
		t.Helper()
		if err := q.RecordAttributionChain(ctx, database.RecordAttributionChainParams{
			ExecutorID: executor, ChainID: chain, Anchor: []byte{9}, T0Ns: t0.UnixNano(), IntervalNs: int64(interval),
			DelayEpochs: 15, ChainLength: 100, TagSpec: 1, SeenNs: seen.UnixNano(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	record(t0.Add(time.Hour))
	record(t0) // an older observation keeps the later last_seen and the first first_seen
	row, err := q.GetAttributionChain(ctx, database.GetAttributionChainParams{ExecutorID: executor, ChainID: chain})
	if err != nil || row.FirstSeenNs != t0.Add(time.Hour).UnixNano() || row.LastSeenNs != t0.Add(time.Hour).UnixNano() {
		t.Fatalf("chain=%+v, %v", row, err)
	}

	for epoch := int64(1); epoch <= 3; epoch++ {
		if err := q.InsertAttributionKey(ctx, database.InsertAttributionKeyParams{ExecutorID: executor, ChainID: chain, Epoch: epoch, Key: []byte{byte(epoch)}, DisclosedAtNs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	// A key is stored once; a repeat keeps the first.
	if err := q.InsertAttributionKey(ctx, database.InsertAttributionKeyParams{ExecutorID: executor, ChainID: chain, Epoch: 2, Key: []byte{0xff}, DisclosedAtNs: 2}); err != nil {
		t.Fatal(err)
	}
	if key, err := q.GetAttributionKey(ctx, database.GetAttributionKeyParams{ExecutorID: executor, ChainID: chain, Epoch: 2}); err != nil || !bytes.Equal(key, []byte{2}) {
		t.Fatalf("key 2=%x, %v", key, err)
	}
	keys, err := q.ListAttributionKeys(ctx, database.ListAttributionKeysParams{ExecutorID: executor, ChainID: chain, FromEpoch: 2, ToEpoch: 9})
	if err != nil || len(keys) != 2 || keys[0].Epoch != 2 || keys[1].Epoch != 3 {
		t.Fatalf("keys=%+v, %v", keys, err)
	}

	run := cbCreate(t, ctx, q, cbIncarnation, cbSession)
	from, to := t0.Add(10*time.Minute), t0.Add(20*time.Minute)
	if err := q.RecordAttributionRun(ctx, database.RecordAttributionRunParams{DebugletID: run.ID, ChainID: chain, SourceIp: "192.0.2.7", SourceIpObserved: 1, ActiveFromNs: from.UnixNano(), ActiveToNs: to.UnixNano()}); err != nil {
		t.Fatal(err)
	}
	candidates := func(ip string, at time.Time) []database.ListAttributionCandidatesRow {
		t.Helper()
		rows, err := q.ListAttributionCandidates(ctx, database.ListAttributionCandidatesParams{SourceIp: ip, AtNs: at.UnixNano(), MaxRows: 33})
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	for _, tc := range []struct {
		name string
		ip   string
		at   time.Time
		want int
	}{
		{"inside", "192.0.2.7", from.Add(time.Minute), 1},
		{"one epoch before", "192.0.2.7", from.Add(-interval), 1},
		{"beyond one epoch before", "192.0.2.7", from.Add(-interval - time.Nanosecond), 0},
		{"one epoch after", "192.0.2.7", to.Add(interval), 1},
		{"beyond one epoch after", "192.0.2.7", to.Add(interval + time.Nanosecond), 0},
		{"another address", "192.0.2.8", from.Add(time.Minute), 0},
	} {
		if got := candidates(tc.ip, tc.at); len(got) != tc.want {
			t.Errorf("%s: %d candidates, want %d", tc.name, len(got), tc.want)
		}
	}
	got := candidates("192.0.2.7", from)[0]
	if got.Uuid != run.Uuid || got.ExecutorID != executor || got.DisclosedThrough != 3 || got.DelayEpochs != 15 || got.ChainLength != 100 || got.SourceIpObserved != 1 {
		t.Fatalf("candidate=%+v", got)
	}

	// An exit narrows the interval, never widens it or inverts it.
	if err := q.EndAttributionRun(ctx, database.EndAttributionRunParams{EndedNs: from.Add(2 * time.Minute).UnixNano(), Uuid: run.Uuid}); err != nil {
		t.Fatal(err)
	}
	if err := q.EndAttributionRun(ctx, database.EndAttributionRunParams{EndedNs: to.UnixNano(), Uuid: run.Uuid}); err != nil {
		t.Fatal(err)
	}
	if got := candidates("192.0.2.7", from); len(got) != 1 || got[0].ActiveToNs != from.Add(2*time.Minute).UnixNano() {
		t.Fatalf("narrowed candidate=%+v", got)
	}
	if err := q.EndAttributionRun(ctx, database.EndAttributionRunParams{EndedNs: from.Add(-time.Hour).UnixNano(), Uuid: run.Uuid}); err != nil {
		t.Fatal(err)
	}
	if got := candidates("192.0.2.7", from); len(got) != 1 || got[0].ActiveToNs != from.UnixNano() {
		t.Fatalf("inverted candidate=%+v", got)
	}
}

func TestAttributionPruneFollowsTheCutoff(t *testing.T) {
	ctx, db := cbOpen(t, 14)
	q := database.New(db)
	const executor = "binding-executor"
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, chain := range []string{"old", "live"} {
		if err := q.RecordAttributionChain(ctx, database.RecordAttributionChainParams{
			ExecutorID: executor, ChainID: chain, Anchor: []byte(chain), T0Ns: t0.UnixNano(), IntervalNs: int64(time.Hour), DelayEpochs: 2, TagSpec: 1, SeenNs: t0.UnixNano(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Epoch 1 of the live chain ends at t0+2h, epoch 5 at t0+6h.
	for _, epoch := range []int64{1, 5} {
		if err := q.InsertAttributionKey(ctx, database.InsertAttributionKeyParams{ExecutorID: executor, ChainID: "live", Epoch: epoch, Key: []byte{1}, DisclosedAtNs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	oldRun, liveRun := cbCreate(t, ctx, q, cbIncarnation, cbSession), cbCreate(t, ctx, q, cbIncarnation, cbSession)
	for _, r := range []struct {
		id int64
		to time.Time
	}{{oldRun.ID, t0.Add(time.Hour)}, {liveRun.ID, t0.Add(5 * time.Hour)}} {
		if err := q.RecordAttributionRun(ctx, database.RecordAttributionRunParams{DebugletID: r.id, ChainID: "live", SourceIp: "192.0.2.7", SourceIpObserved: 1, ActiveFromNs: t0.UnixNano(), ActiveToNs: r.to.UnixNano()}); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := t0.Add(3 * time.Hour).UnixNano()
	if n, err := q.PruneAttributionRuns(ctx, cutoff); err != nil || n != 1 {
		t.Fatalf("pruned runs=%d, %v", n, err)
	}
	if n, err := q.PruneAttributionKeys(ctx, cutoff); err != nil || n != 1 {
		t.Fatalf("pruned keys=%d, %v", n, err)
	}
	// The old chain has neither keys nor runs left; the live one keeps both.
	if n, err := q.PruneAttributionChains(ctx, cutoff); err != nil || n != 1 {
		t.Fatalf("pruned chains=%d, %v", n, err)
	}
	if _, err := q.GetAttributionChain(ctx, database.GetAttributionChainParams{ExecutorID: executor, ChainID: "live"}); err != nil {
		t.Fatalf("live chain pruned: %v", err)
	}
	if err := q.AdvanceAttributionRetention(ctx, cutoff); err != nil {
		t.Fatal(err)
	}
	if err := q.AdvanceAttributionRetention(ctx, cutoff-1); err != nil {
		t.Fatal(err)
	}
	if got, err := q.GetAttributionRetention(ctx); err != nil || got < cutoff {
		t.Fatalf("retained_from=%d, %v; want it to stay at least %d", got, err, cutoff)
	}
}
