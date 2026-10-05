// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
)

const retiredSeed = "retired chain seed"

// retiredTesla is a short chain: I = 1 s, L = 6, d = 2, so the final key is
// due 7 s after the chain's origin.
func retiredTesla(seed string) config.TeslaConfig {
	return config.TeslaConfig{Seed: seed, EpochSeconds: 1, DisclosureDelayEpochs: 2, ChainLength: 6}
}

// retiredChainRow records generation as a chain derived from retiredSeed.
func retiredChainRow(t *testing.T, db *sql.DB, generation int64, origin time.Time, delay sql.NullInt64) []byte {
	t.Helper()
	tail, err := tesla.ChainSeed([]byte(retiredSeed), generation)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: tail, EpochLength: time.Second, DisclosureDelay: 2, ChainLength: 6})
	if err != nil {
		t.Fatal(err)
	}
	if err := executordb.New(db).CreateTeslaChain(t.Context(), executordb.CreateTeslaChainParams{Generation: generation, Anchor: ks.Anchor(),
		EpochBase: origin.UTC(), DelayNs: int64(time.Second), ChainLength: 6, CreatedAt: origin.UTC(), DisclosureDelay: delay}); err != nil {
		t.Fatal(err)
	}
	return ks.Anchor()
}

// A start after a restart re-derives the previous chain from the seed and its
// record, and its holder hands the heartbeat each key of the old chain from
// the instant it is due, under the old anchor, up to k_{L-1}; the old chain
// never signs again, and a new run's tagger signs with the new chain only.
func TestRestartDisclosesTheRetiredChainTail(t *testing.T) {
	ctx := t.Context()
	db := newFixtureDatabase(t)
	cfg := retiredTesla(retiredSeed)
	first, generation, _, err := startChain(ctx, db, cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, next, _, err := startChain(ctx, db, cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	if generation != 1 || next != 2 || bytes.Equal(first.Anchor(), second.Anchor()) {
		t.Fatalf("starts recorded generations %d and %d with anchors %x and %x", generation, next, first.Anchor(), second.Anchor())
	}
	origin := first.Config().Epoch
	recorded, err := executordb.New(db).GetTeslaChain(ctx, 1)
	if err != nil || !recorded.EpochBase.Equal(origin) || recorded.DisclosureDelay != (sql.NullInt64{Int64: 2, Valid: true}) {
		t.Fatalf("recorded chain %+v (%v); want origin %v and d = 2", recorded, err, origin)
	}

	core, logs := observer.New(zapcore.InfoLevel)
	retired := deriveRetiredChain(ctx, executordb.New(db), cfg.Seed, next, true, origin.Add(3500*time.Millisecond), zap.New(core))
	if retired == nil || !bytes.Equal(retired.Anchor(), first.Anchor()) || !retired.Config().DisclosureOnly {
		t.Fatalf("re-derived chain %v; want the first chain, disclosure only", retired)
	}
	if n := logs.FilterMessage("Disclosing the previous TESLA chain's remaining keys").Len(); n != 1 || logs.Len() != 1 {
		t.Fatalf("logged %v; want one disclosure line", logs.All())
	}

	holder := &retiredChain{schedule: retired}
	for k := int64(0); k <= 8; k++ {
		at := origin.Add(time.Duration(k)*time.Second + 500*time.Millisecond)
		got := holder.disclosures(at)
		switch {
		case k < 2 || k == 8:
			if len(got) != 0 {
				t.Fatalf("epoch %d: disclosed %v; want nothing", k, got)
			}
		default:
			want := min(k-2, 5)
			key, _ := first.KeyAtEpoch(want)
			if len(got) != 1 || !bytes.Equal(got[0].GetAnchor(), first.Anchor()) || got[0].GetEpoch() != want || !bytes.Equal(got[0].GetKey(), key) {
				t.Fatalf("epoch %d: disclosed %v; want k_%d of the first chain", k, got, want)
			}
		}
		if retired.CurrentKey(at) != nil {
			t.Fatalf("epoch %d: the retired chain returned a signing key", k)
		}
	}
	if holder.schedule != nil || len(holder.disclosures(origin.Add(3500*time.Millisecond))) != 0 {
		t.Fatal("the retired chain was kept after its final disclosure")
	}

	// The tagger of a run after the restart holds the new chain; a longer
	// epoch keeps the check inside epoch 1. The anchor does not depend on it.
	tail, err := tesla.ChainSeed([]byte(retiredSeed), next)
	if err != nil {
		t.Fatal(err)
	}
	current, err := tesla.NewKeySchedule(tesla.Config{Seed: tail, EpochLength: time.Minute, DisclosureDelay: 2, ChainLength: 6, Epoch: time.Now().Add(-90 * time.Second)})
	if err != nil || !bytes.Equal(current.Anchor(), second.Anchor()) {
		t.Fatalf("new chain %v: anchor %x; want %x", err, current.Anchor(), second.Anchor())
	}
	run := []byte("00000000-0000-4000-8000-000000000071")
	pkt := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7, 0x30, 0x39, 0, 0x35, 0, 8, 0, 0}
	tg := tagger.New(current, run)
	tagged, err := tg.TagPacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	key := current.CurrentKey(time.Now())
	if ok, err := tesla.VerifyTag(key, 1, run, tagged, tagger.ReadIPID(tagged)); err != nil || !ok || !bytes.Equal(tg.Schedule().Anchor(), second.Anchor()) {
		t.Fatalf("the new run's tag does not verify with the new chain: %v, %v", ok, err)
	}
	for epoch := int64(0); epoch <= 6; epoch++ {
		if old, _ := first.KeyAtEpoch(epoch); bytes.Equal(key, old) {
			t.Fatalf("the new run signs with k_%d of the retired chain", epoch)
		}
	}
}

// Without everything a re-derivation needs, a start discloses no tail and
// says once why: no seed, no recorded delay (a chain recorded before the
// column, migrated from schema 6), a final key already due, an unready clock,
// or a re-derived anchor that is not the recorded one, which is an error.
func TestRetiredChainIsNotDerived(t *testing.T) {
	now := time.Now()
	recentDelay := sql.NullInt64{Int64: 2, Valid: true}
	for _, tc := range []struct {
		name       string
		seed       string
		clockReady bool
		record     func(t *testing.T, db *sql.DB)
		level      zapcore.Level
		message    string
		reason     string
	}{
		{"first chain", retiredSeed, true, func(*testing.T, *sql.DB) {}, 0, "", ""},
		{"no seed", "", true, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, recentDelay) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "no tesla.seed is configured, so the chain cannot be re-derived"},
		{"unknown delay", retiredSeed, true, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, sql.NullInt64{}) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "the chain's disclosure delay is not on record"},
		{"final key due", retiredSeed, true, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now.Add(-time.Hour), recentDelay) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "its final key is already due"},
		{"clock unready", retiredSeed, false, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, recentDelay) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "the host clock is not ready"},
		{"anchor mismatch", "another seed", true, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, recentDelay) },
			zapcore.ErrorLevel, "Re-derived previous TESLA chain does not match its recorded anchor; its remaining keys are not disclosed (was tesla.seed changed?)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newFixtureDatabase(t)
			tc.record(t, db)
			next, err := executordb.New(db).NextTeslaChainGeneration(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			core, logs := observer.New(zapcore.DebugLevel)
			if retired := deriveRetiredChain(t.Context(), executordb.New(db), tc.seed, next, tc.clockReady, now.Add(time.Second), zap.New(core)); retired != nil {
				t.Fatal("a retired chain was derived")
			}
			if tc.message == "" {
				if logs.Len() != 0 {
					t.Fatalf("logged %v; want nothing", logs.All())
				}
				return
			}
			entries := logs.All()
			if len(entries) != 1 || entries[0].Level != tc.level || entries[0].Message != tc.message || (tc.reason != "" && entries[0].ContextMap()["reason"] != tc.reason) {
				t.Fatalf("logged %v; want one %s line %q (%s)", entries, tc.level, tc.message, tc.reason)
			}
		})
	}
}

// Migration 7 adds the delay as NULL to chains recorded on schema 6, and such
// a chain is not re-derived.
func TestChainRecordedBeforeTheDelayColumn(t *testing.T) {
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "executor.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if version, err := sqlitedb.Migrate(t.Context(), db, executordb.MigrationFS(), 6); err != nil || version != 6 {
		t.Fatalf("migrate to 6: %d, %v", version, err)
	}
	if _, err := db.ExecContext(t.Context(), "INSERT INTO tesla_chains (generation, anchor, epoch_base, delay_ns, chain_length, created_at) VALUES (1, x'0102', ?, 1000000000, 6, ?)", time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if version, err := sqlitedb.Migrate(t.Context(), db, executordb.MigrationFS(), sqlitedb.Latest); err != nil || version != 7 {
		t.Fatalf("migrate to latest: %d, %v", version, err)
	}
	chain, err := executordb.New(db).GetTeslaChain(t.Context(), 1)
	if err != nil || chain.DisclosureDelay.Valid {
		t.Fatalf("migrated chain %+v, %v; want an unknown delay", chain, err)
	}
	core, logs := observer.New(zapcore.InfoLevel)
	if deriveRetiredChain(t.Context(), executordb.New(db), retiredSeed, 2, true, time.Now(), zap.New(core)) != nil || logs.FilterField(zap.String("reason", "the chain's disclosure delay is not on record")).Len() != 1 {
		t.Fatalf("a chain without a recorded delay: logged %v", logs.All())
	}
}

// heartbeatCapture is a dispatcher that records the heartbeats it receives.
type heartbeatCapture struct {
	pb.DispatcherServiceClient
	mu    sync.Mutex
	beats []*pb.HeartbeatRequest
}

func (c *heartbeatCapture) Heartbeat(_ context.Context, req *pb.HeartbeatRequest, _ ...grpc.CallOption) (*pb.HeartbeatResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beats = append(c.beats, req)
	return &pb.HeartbeatResponse{}, nil
}

func (c *heartbeatCapture) received() []*pb.HeartbeatRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*pb.HeartbeatRequest(nil), c.beats...)
}

// A node restarted on the same database before the previous chain's final
// disclosure keeps that chain disclosure only; its heartbeats carry the old
// chain's due keys under the old anchor, never early, through k_{L-1}, and
// stop once the chain is dropped.
func TestHeartbeatDisclosesTheRetiredChainTail(t *testing.T) {
	db := newFixtureDatabase(t)
	cfg := fixtureConfig()
	cfg.Tesla = retiredTesla(retiredSeed)
	start := func() *Node {
		t.Helper()
		node, err := newNode(cfg, zap.NewNop(), db, ratelimit.New)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := node.Close(); err != nil {
				t.Error(err)
			}
		})
		return node
	}
	first := start().schedule
	node := start()
	retired := node.retired.schedule
	if node.schedule.Config().ClockUnready {
		// This host's clock is not ready: the start must not have derived
		// the tail; the heartbeat path is still exercised on a derivation
		// made as on a ready clock.
		if retired != nil {
			t.Fatal("a start on an unready clock derived the previous chain")
		}
		retired = deriveRetiredChain(t.Context(), executordb.New(db), cfg.Tesla.Seed, 2, true, time.Now(), zap.NewNop())
		node.retired.schedule = retired
	}
	if retired == nil || !bytes.Equal(retired.Anchor(), first.Anchor()) || !retired.Config().DisclosureOnly {
		t.Fatalf("restarted node holds %v; want the first chain, disclosure only", retired)
	}

	e, err := newExecutor(node, &abortTestScheduler{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &heartbeatCapture{}
	e.clientFor = func(context.Context, controlsession.Binding) (pb.DispatcherServiceClient, error) {
		return dispatcher, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.startHeartbeatLoop(ctx, operationBinding()) }()
	origin := first.Config().Epoch
	dropped := origin.Add(8 * time.Second)
	deadline := dropped.Add(operationTestBound)
	for {
		beats := dispatcher.received()
		if n := len(beats); n > 0 && time.Unix(0, beats[n-1].GetTimestampNs()).After(dropped) {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("no heartbeat after the retired chain's final disclosure")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	highest := int64(-1)
	for _, beat := range dispatcher.received() {
		sent := time.Unix(0, beat.GetTimestampNs())
		if len(beat.GetTeslaKeyAnchor()) != 0 {
			t.Fatalf("the current chain's key names anchor %x", beat.GetTeslaKeyAnchor())
		}
		for epoch := int64(0); epoch <= 6 && beat.GetTeslaKey() != nil; epoch++ {
			if old, _ := first.KeyAtEpoch(epoch); bytes.Equal(beat.GetTeslaKey(), old) {
				t.Fatalf("the current chain's disclosure is k_%d of the retired chain", epoch)
			}
		}
		extra := beat.GetExtraDisclosures()
		if !sent.Before(dropped) {
			if len(extra) != 0 {
				t.Fatalf("a heartbeat after the drop carried %v", extra)
			}
			continue
		}
		if len(extra) == 0 {
			continue
		}
		disclosure := extra[0]
		due := int64(sent.Sub(origin)/time.Second) - 2
		key, _ := first.KeyAtEpoch(disclosure.GetEpoch())
		if len(extra) != 1 || !bytes.Equal(disclosure.GetAnchor(), first.Anchor()) || disclosure.GetEpoch() > due || !bytes.Equal(disclosure.GetKey(), key) {
			t.Fatalf("heartbeat %d ms after the origin carried %v; want one first-chain key of an epoch up to %d", sent.Sub(origin).Milliseconds(), extra, due)
		}
		highest = max(highest, disclosure.GetEpoch())
	}
	if highest != 5 || node.retired.schedule != nil {
		t.Fatalf("highest retired key disclosed k_%d, chain kept %v; want k_5 and dropped", highest, node.retired.schedule != nil)
	}
}
