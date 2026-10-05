// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
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
	retired := deriveRetiredChain(ctx, executordb.New(db), cfg.Seed, next, true, nil, origin.Add(3500*time.Millisecond), zap.New(core))
	if retired == nil || !bytes.Equal(retired.Anchor(), first.Anchor()) || !retired.Config().DisclosureOnly {
		t.Fatalf("re-derived chain %v; want the first chain, disclosure only", retired)
	}
	if n := logs.FilterMessage("Disclosing the previous TESLA chain's remaining keys").Len(); n != 1 || logs.Len() != 1 {
		t.Fatalf("logged %v; want one disclosure line", logs.All())
	}

	holder := &retiredChain{schedule: retired, logger: zap.NewNop()}
	for k := int64(0); k <= 8; k++ {
		at := origin.Add(time.Duration(k)*time.Second + 500*time.Millisecond)
		got := holder.disclosures(at)
		switch {
		case k < 2:
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
	// Past its final disclosure the chain is kept until the final key was
	// delivered; an earlier key does not retire it.
	holder.delivered(holder.disclosures(origin.Add(4500 * time.Millisecond)))
	if holder.schedule == nil {
		t.Fatal("delivering k_2 retired the chain")
	}
	holder.delivered(holder.disclosures(origin.Add(20 * time.Second)))
	if holder.schedule != nil || len(holder.disclosures(origin.Add(20*time.Second))) != 0 {
		t.Fatal("the retired chain was kept after its final key was delivered")
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
// column, migrated from schema 6), a final key due more than a day ago, an
// unready clock,
// tagger filters of the earlier process not retired, or a re-derived anchor
// that is not the recorded one, which is an error.
func TestRetiredChainIsNotDerived(t *testing.T) {
	now := time.Now()
	recentDelay := sql.NullInt64{Int64: 2, Valid: true}
	for _, tc := range []struct {
		name       string
		seed       string
		clockReady bool
		signers    error
		record     func(t *testing.T, db *sql.DB)
		level      zapcore.Level
		message    string
		reason     string
	}{
		{"first chain", retiredSeed, true, nil, func(*testing.T, *sql.DB) {}, 0, "", ""},
		{"no seed", "", true, nil, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, recentDelay) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "no tesla.seed is configured, so the chain cannot be re-derived"},
		{"unknown delay", retiredSeed, true, nil, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, sql.NullInt64{}) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "the chain's disclosure delay is not on record"},
		{"final key due too long ago", retiredSeed, true, nil, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now.Add(-25*time.Hour), recentDelay) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "its final key was due more than 24 hours ago"},
		{"clock unready", retiredSeed, false, nil, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, recentDelay) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "the host clock is not ready"},
		{"signers not retired", retiredSeed, true, errors.New("delete stale egress filter"), func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, recentDelay) },
			zapcore.InfoLevel, "Previous TESLA chain's remaining keys are not disclosed", "tagger filters of the earlier process could not be retired"},
		{"anchor mismatch", "another seed", true, nil, func(t *testing.T, db *sql.DB) { retiredChainRow(t, db, 1, now, recentDelay) },
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
			if retired := deriveRetiredChain(t.Context(), executordb.New(db), tc.seed, next, tc.clockReady, tc.signers, now.Add(time.Second), zap.New(core)); retired != nil {
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
	if deriveRetiredChain(t.Context(), executordb.New(db), retiredSeed, 2, true, nil, time.Now(), zap.New(core)) != nil || logs.FilterField(zap.String("reason", "the chain's disclosure delay is not on record")).Len() != 1 {
		t.Fatalf("a chain without a recorded delay: logged %v", logs.All())
	}
}

// heartbeatCapture is a dispatcher that records the heartbeats it receives
// and fails those fail names.
type heartbeatCapture struct {
	pb.DispatcherServiceClient
	mu    sync.Mutex
	beats []*pb.HeartbeatRequest
	fail  func(*pb.HeartbeatRequest) error
}

func (c *heartbeatCapture) Heartbeat(_ context.Context, req *pb.HeartbeatRequest, _ ...grpc.CallOption) (*pb.HeartbeatResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beats = append(c.beats, req)
	if c.fail != nil {
		if err := c.fail(req); err != nil {
			return nil, err
		}
	}
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
// stop after one that carried k_{L-1} succeeded.
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
		retired = deriveRetiredChain(t.Context(), executordb.New(db), cfg.Tesla.Seed, 2, true, nil, time.Now(), zap.NewNop())
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
	final, _ := first.KeyAtEpoch(5)
	deliveredAt := -1
	deadline := origin.Add(8 * time.Second).Add(operationTestBound)
	for {
		beats := dispatcher.received()
		if deliveredAt < 0 {
			for i, beat := range beats {
				if extra := beat.GetExtraDisclosures(); len(extra) == 1 && bytes.Equal(extra[0].GetKey(), final) {
					deliveredAt = i
					break
				}
			}
		}
		if deliveredAt >= 0 && len(beats) > deliveredAt+2 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("no heartbeat after one delivered the retired chain's final key")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	highest := int64(-1)
	for i, beat := range dispatcher.received() {
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
		if i > deliveredAt {
			if len(extra) != 0 {
				t.Fatalf("a heartbeat after the final key was delivered carried %v", extra)
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
		t.Fatalf("highest retired key disclosed k_%d, chain kept %v; want k_5 and retired", highest, node.retired.schedule != nil)
	}
}

// After recovery the retired chain's epochs advance on the monotonic clock
// from the recovery instant: a forward or backward wall step, or a wall clock
// that drifts beyond what a signing chain tolerates (readiness lost), leaves
// its disclosure schedule unchanged and disclosure continues.
func TestRetiredChainFollowsTheMonotonicClock(t *testing.T) {
	origin := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	recovery := origin.Add(3500 * time.Millisecond)
	tail, err := tesla.ChainSeed([]byte(retiredSeed), 1)
	if err != nil {
		t.Fatal(err)
	}
	schedule := func(step time.Duration) *tesla.KeySchedule {
		t.Helper()
		var host tesla.Clock
		if step != 0 {
			host = aheadClock(step)
		}
		ks, err := tesla.NewKeySchedule(tesla.Config{Seed: tail, EpochLength: time.Second, DisclosureDelay: 2, ChainLength: 6, Epoch: origin,
			DisclosureOnly: true, Clock: recoveredClock{wall: recovery, at: recovery, host: host}})
		if err != nil {
			t.Fatal(err)
		}
		return ks
	}
	unstepped := schedule(0)
	for _, step := range []time.Duration{30 * time.Second, -30 * time.Second, time.Hour} {
		stepped := schedule(step)
		for at := time.Duration(0); at <= 10*time.Second; at += 250 * time.Millisecond {
			now := recovery.Add(at)
			wantEpoch, wantKey, wantOK := unstepped.DisclosedKey(now)
			epoch, key, ok := stepped.DisclosedKey(now)
			if epoch != wantEpoch || ok != wantOK || !bytes.Equal(key, wantKey) {
				t.Fatalf("wall step %v, %v after recovery: disclosed (%d, %v); want (%d, %v)", step, at, epoch, ok, wantEpoch, wantOK)
			}
		}
		if drift := stepped.Drift(recovery.Add(time.Second)); drift != step {
			t.Fatalf("drift %v after a wall step of %v", drift, step)
		}
	}
	if epoch, _, ok := unstepped.DisclosedKey(recovery); !ok || epoch != 1 {
		t.Fatalf("disclosed (%d, %v) at recovery 3.5 s after the origin; want k_1", epoch, ok)
	}
}

// steppedRetiredClock observes t after a wall step; only its wall reading
// includes the step, as on a host whose monotonic clock continued normally.
type steppedRetiredClock time.Duration

func (c steppedRetiredClock) Elapsed(origin, t time.Time) (time.Duration, time.Duration) {
	wall := t.Sub(origin)
	return wall - time.Duration(c), wall
}

func TestRetiredChainRetentionFollowsTheMonotonicClock(t *testing.T) {
	origin := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	recovery := origin.Add(25 * time.Second)
	for _, step := range []time.Duration{25 * time.Hour, -25 * time.Hour} {
		t.Run(step.String(), func(t *testing.T) {
			schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte(retiredSeed), EpochLength: time.Second, DisclosureDelay: 11, ChainLength: 20,
				Epoch: origin, DisclosureOnly: true, Clock: recoveredClock{wall: recovery, at: recovery, host: steppedRetiredClock(step)}})
			if err != nil {
				t.Fatal(err)
			}
			holder := &retiredChain{schedule: schedule, logger: zap.NewNop()}
			for _, check := range []struct {
				since time.Duration
				epoch int64
			}{
				{time.Second, 15},
				{5 * time.Second, 19},
				{5*time.Second + retiredDeliveryLimit - time.Nanosecond, 19},
			} {
				got := holder.disclosures(recovery.Add(check.since + step))
				key, _ := schedule.KeyAtEpoch(check.epoch)
				if holder.schedule == nil || len(got) != 1 || got[0].GetEpoch() != check.epoch || !bytes.Equal(got[0].GetKey(), key) {
					t.Fatalf("%v since recovery with wall step %v: disclosed %v, kept %v; want k_%d", check.since, step, got, holder.schedule != nil, check.epoch)
				}
			}
			if got := holder.disclosures(recovery.Add(5*time.Second + retiredDeliveryLimit + step)); holder.schedule != nil || len(got) != 0 {
				t.Fatalf("retained the chain beyond the elapsed retention interval: %v", got)
			}
		})
	}
}

// A retired chain stays until a heartbeat delivered its final key, however
// the heartbeat cadence changed: the previous chain had I = 1 s, d = 11 and
// L = 20, so k_19 is due 30 s after its origin; the restart at +25 s runs
// 60 s epochs, whose heartbeat interval is 30 s, so the first heartbeat after
// the restart comes at +55 s. Without a delivery the chain is dropped with a
// warning a day after its final disclosure.
func TestRetiredChainOutlivesAChangedHeartbeatCadence(t *testing.T) {
	db := newFixtureDatabase(t)
	origin := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	tail, err := tesla.ChainSeed([]byte(retiredSeed), 1)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := tesla.NewKeySchedule(tesla.Config{Seed: tail, EpochLength: time.Second, DisclosureDelay: 11, ChainLength: 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := executordb.New(db).CreateTeslaChain(t.Context(), executordb.CreateTeslaChainParams{Generation: 1, Anchor: previous.Anchor(),
		EpochBase: origin, DelayNs: int64(time.Second), ChainLength: 20, CreatedAt: origin, DisclosureDelay: sql.NullInt64{Int64: 11, Valid: true}}); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zapcore.InfoLevel)
	retired := deriveRetiredChain(t.Context(), executordb.New(db), retiredSeed, 2, true, nil, origin.Add(25*time.Second), zap.New(core))
	if retired == nil {
		t.Fatalf("not derived: %v", logs.All())
	}
	finalKey, _ := previous.KeyAtEpoch(19)
	for _, cap := range []bool{false, true} {
		holder := &retiredChain{schedule: retired, logger: zap.New(core)}
		if cap {
			if got := holder.disclosures(retired.FinalDisclosure().Add(retiredDeliveryLimit)); len(got) != 0 || holder.schedule != nil {
				t.Fatalf("a day after the final disclosure: disclosed %v, kept %v", got, holder.schedule != nil)
			}
			if logs.FilterMessage("Dropped the previous TESLA chain without a delivered final key").Len() != 1 {
				t.Fatal("the undelivered drop was not logged")
			}
			continue
		}
		got := holder.disclosures(origin.Add(55 * time.Second))
		if len(got) != 1 || got[0].GetEpoch() != 19 || !bytes.Equal(got[0].GetKey(), finalKey) {
			t.Fatalf("first heartbeat after the restart carried %v; want k_19", got)
		}
		holder.delivered(got)
		if holder.schedule != nil {
			t.Fatal("the chain was kept after its final key was delivered")
		}
	}
}

// A heartbeat that carried the retired chain's final key and failed keeps
// the chain; the next one that succeeds retires it.
func TestFailedHeartbeatKeepsTheRetiredChain(t *testing.T) {
	cfg := fixtureConfig()
	cfg.Tesla = retiredTesla("")
	node, err := newNode(cfg, zap.NewNop(), newFixtureDatabase(t), ratelimit.New)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := node.Close(); err != nil {
			t.Error(err)
		}
	})
	// The chain's final key has been due for 3 s.
	retired, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte("failed delivery"), EpochLength: time.Second, DisclosureDelay: 2, ChainLength: 6,
		Epoch: time.Now().Add(-10 * time.Second).Round(0), DisclosureOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	node.retired.schedule, node.retired.logger = retired, zap.NewNop()
	final, _ := retired.KeyAtEpoch(5)

	e, err := newExecutor(node, &abortTestScheduler{})
	if err != nil {
		t.Fatal(err)
	}
	failures := 0
	dispatcher := &heartbeatCapture{fail: func(req *pb.HeartbeatRequest) error {
		if len(req.GetExtraDisclosures()) > 0 && failures < 2 {
			failures++
			return errors.New("dispatcher unavailable")
		}
		return nil
	}}
	e.clientFor = func(context.Context, controlsession.Binding) (pb.DispatcherServiceClient, error) {
		return dispatcher, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.startHeartbeatLoop(ctx, operationBinding()) }()
	// Five heartbeats at the 500 ms interval of 1 s epochs, plus the usual bound.
	deadline := time.Now().Add(5*cfg.Tesla.EpochLength()/2 + operationTestBound)
	for len(dispatcher.received()) < 5 {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("too few heartbeats")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	for i, beat := range dispatcher.received() {
		extra := beat.GetExtraDisclosures()
		if i < 3 {
			if len(extra) != 1 || extra[0].GetEpoch() != 5 || !bytes.Equal(extra[0].GetKey(), final) {
				t.Fatalf("heartbeat %d carried %v; want the final key again", i, extra)
			}
			continue
		}
		if len(extra) != 0 {
			t.Fatalf("heartbeat %d after the delivery carried %v", i, extra)
		}
	}
	if node.retired.schedule != nil {
		t.Fatal("the delivered chain was kept")
	}
}

// A start after the previous chain's final key was due, within the bound a
// running process keeps an undelivered chain for, still reconstructs it, and
// the first heartbeat carries k_{L-1}.
func TestRetiredChainPastItsFinalDisclosure(t *testing.T) {
	db := newFixtureDatabase(t)
	now := time.Now()
	anchor := retiredChainRow(t, db, 1, now.Add(-time.Hour), sql.NullInt64{Int64: 2, Valid: true})
	retired := deriveRetiredChain(t.Context(), executordb.New(db), retiredSeed, 2, true, nil, now, zap.NewNop())
	if retired == nil || !bytes.Equal(retired.Anchor(), anchor) {
		t.Fatal("a chain an hour past its final disclosure was not reconstructed")
	}
	holder := &retiredChain{schedule: retired, logger: zap.NewNop()}
	got := holder.disclosures(now.Add(time.Second))
	if len(got) != 1 || got[0].GetEpoch() != 5 || !bytes.Equal(got[0].GetAnchor(), anchor) {
		t.Fatalf("first heartbeat carried %v; want k_5", got)
	}
	holder.delivered(got)
	if holder.schedule != nil {
		t.Fatal("the delivered chain was kept")
	}
}
