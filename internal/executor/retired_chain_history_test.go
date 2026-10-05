// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"io/fs"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/api"
	dispatcherrpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/tagspec"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// A capture from a stopped executor is verified from public history after
// both databases reopen. Clock readiness is controlled as in the other tail
// fixtures; real attachment retirement is covered by the kernel tests.
func TestRetainedCaptureSurvivesExecutorAndDispatcherRestart(t *testing.T) {
	ctx, logger := t.Context(), zap.NewNop()
	open := func(path string, migrations fs.FS) *sql.DB {
		t.Helper()
		db, err := sqlitedb.Open(path, sqlitedb.Create())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := sqlitedb.Migrate(ctx, db, migrations, sqlitedb.Latest); err != nil {
			t.Fatal(err)
		}
		return db
	}
	root := t.TempDir()
	executorPath, dispatcherPath := filepath.Join(root, "executor.sqlite"), filepath.Join(root, "dispatcher.sqlite")
	executorDB := open(executorPath, executordb.MigrationFS())
	dispatcherDB := open(dispatcherPath, dispatcherdb.MigrationFS())
	const executorID = "retained-capture"
	runID := uuid.MustParse("00000000-0000-4000-8000-000000000071")
	origin := time.Now().Add(-20 * time.Second)
	// Eleven seconds of delay cover the verifier's skew and tolerance bounds.
	anchor := retiredChainRow(t, executorDB, 1, origin, sql.NullInt64{Int64: 11, Valid: true})
	seed, err := tesla.ChainSeed([]byte(retiredSeed), 1)
	if err != nil {
		t.Fatal(err)
	}
	old, err := tesla.NewKeySchedule(tesla.Config{Seed: seed, Epoch: origin, EpochLength: time.Second, DisclosureDelay: 11, ChainLength: 6})
	if err != nil || !bytes.Equal(old.Anchor(), anchor) {
		t.Fatalf("old schedule: %v", err)
	}
	packet := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7, 0x30, 0x39, 0, 0x35, 0, 8, 0, 0}
	key, _ := old.KeyAtEpoch(1)
	packetTag, err := tesla.TagWithKey(key, []byte(runID.String()), packet)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(packet[4:], packetTag)
	capture := client.CapturedPacket{Data: packet, CapturedAt: origin.Add(1250 * time.Millisecond), LinkType: 101}

	startDispatcher := func(db *sql.DB) *dispatcher.Dispatcher {
		t.Helper()
		payment, err := payments.NewPaymentHandler(db, &dispatcherconfig.DispatcherConfig{Sui: dispatcherconfig.SuiConfig{Disabled: true}}, logger)
		if err != nil {
			t.Fatal(err)
		}
		d, err := dispatcher.New(logger, db, "retained-history", time.Minute, time.Second, payment)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(d.Close)
		return d
	}
	d := startDispatcher(dispatcherDB)
	register := func(schedule *tesla.KeySchedule) *dispatcherrpc.SessionOwner {
		t.Helper()
		binding, err := controlsession.NewBinding(d.ControlIncarnation())
		if err != nil {
			t.Fatal(err)
		}
		owner, err := dispatcherrpc.NewSessionOwner(executorID, binding, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { owner.Retire() })
		setup, err := owner.AdmitSetup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer setup.Finish()
		cfg := schedule.Config()
		err = d.RegisterExecutor(setup.Context(), owner, &pb.HelloResponse{
			ExecutorId: executorID, Currency: "TEST", TeslaAnchorKey: schedule.Anchor(), TeslaAnchorTimestampNs: cfg.Epoch.UnixNano(),
			TeslaDelaySec: 1, TeslaDisclosureDelayEpochs: cfg.DisclosureDelay, TeslaChainLength: cfg.ChainLength,
			Capabilities: &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"udp"}, EnforcementMode: "fallback", Tagging: &pb.TaggingMode{Ipv4: "userspace", Ipv6: "none", Scion: "none", TagSpec: tagspec.ID}},
		}, "192.0.2.1")
		if err != nil || !owner.MarkRegistered() {
			t.Fatalf("register chain: %v", err)
		}
		return owner
	}
	oldOwner := register(old)
	q := dispatcherdb.New(dispatcherDB)
	row, err := q.CreateDebuglet(ctx, dispatcherdb.CreateDebugletParams{Uuid: runID, ExecutorID: executorID,
		StartTime: models.NewUTCTime(origin), EndTime: models.NewUTCTime(origin.Add(2 * time.Second)),
		State: models.RunStateExited, DispatcherIncarnation: oldOwner.Binding().Incarnation, SessionID: oldOwner.Binding().SessionID})
	if err != nil {
		t.Fatal(err)
	}
	chainID := tag.ChainID(anchor)
	if err := q.RecordAttributionRun(ctx, dispatcherdb.RecordAttributionRunParams{DebugletID: row.ID, ChainID: chainID, SourceIp: "192.0.2.1", SourceIpObserved: 1, ActiveFromNs: origin.UnixNano(), ActiveToNs: origin.Add(2 * time.Second).UnixNano()}); err != nil {
		t.Fatal(err)
	}
	// The fixture's retained history starts before its controlled capture.
	if _, err := dispatcherDB.ExecContext(ctx, "UPDATE attribution_retention SET retained_from_ns = ?", origin.UnixNano()); err != nil {
		t.Fatal(err)
	}

	// The previous process ends. A start on its reopened database records a
	// different generation; only production recovery supplies its old tail.
	if err := executorDB.Close(); err != nil {
		t.Fatal(err)
	}
	executorDB = open(executorPath, executordb.MigrationFS())
	current, generation, _, err := startChain(ctx, executorDB, retiredTesla(retiredSeed), 0)
	if err != nil || generation != 2 || bytes.Equal(current.Anchor(), anchor) {
		t.Fatalf("replacement generation %d: %v", generation, err)
	}
	retired := deriveRetiredChain(ctx, executordb.New(executorDB), retiredSeed, generation, true, nil, origin.Add(3500*time.Millisecond), logger)
	if retired == nil || !retired.Config().DisclosureOnly || retired.CurrentKey(capture.CapturedAt) != nil {
		t.Fatal("old chain was not recovered as disclosure-only")
	}
	oldOwner.Retire()
	owner := register(current)
	holder := &retiredChain{schedule: retired, logger: logger}
	earlier := holder.disclosures(origin.Add(14 * time.Second))
	final := holder.disclosures(origin.Add(17 * time.Second))
	if len(final) != 1 || final[0].Epoch != 5 || len(earlier) != 1 || earlier[0].Epoch != 3 {
		t.Fatal("recovered chain did not disclose the expected epochs")
	}
	for _, disclosures := range [][]*pb.TeslaDisclosure{final, earlier, final} {
		mutation, err := owner.AdmitMutation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.OnHeartbeat(mutation.Context(), mutation, &pb.HeartbeatRequest{ExecutorId: executorID, ExtraDisclosures: disclosures})
		mutation.Finish()
		if err != nil {
			t.Fatal(err)
		}
	}

	verify := func(db *sql.DB, d *dispatcher.Dispatcher) {
		t.Helper()
		e := echo.New()
		api.NewHandler(d, db, logger, api.MetricsStateDirectory(t.TempDir())).RegisterRoutes(e)
		server := httptest.NewServer(e)
		defer server.Close()
		c, err := client.New(server.URL, client.Options{})
		if err != nil {
			t.Fatal(err)
		}
		history, err := c.AttributionCandidates(ctx, "192.0.2.1", capture.CapturedAt)
		if err != nil || len(history.Candidates) != 1 || history.Candidates[0].RunID != runID.String() || history.Candidates[0].Schedule.ChainID != chainID {
			t.Fatalf("historical candidate: %+v, %v", history, err)
		}
		report, err := c.Verify(ctx, []client.CapturedPacket{capture}, client.VerifyOptions{Offline: true})
		if err != nil || len(report.Groups) != 1 || report.Groups[0].Verdict != client.VerdictVerified || report.Groups[0].RunID != runID.String() || report.Groups[0].ExecutorID != executorID || report.Groups[0].Epoch != 1 || report.Groups[0].Method != client.VerifyMethodOffline {
			t.Fatalf("retained capture: %+v, %v", report.Groups, err)
		}
		bad := capture
		bad.Data = bytes.Clone(capture.Data)
		// At epoch 1 the only signing candidate is k_1 (k_0 is public).
		bad.Data[4] ^= 1
		badReport, err := c.Verify(ctx, []client.CapturedPacket{bad}, client.VerifyOptions{Offline: true})
		if err != nil || len(badReport.Groups) != 1 || badReport.Groups[0].Verdict != client.VerdictInvalid {
			t.Fatalf("altered capture: %+v, %v", badReport.Groups, err)
		}
		keys, err := dispatcherdb.New(db).ListAttributionKeys(ctx, dispatcherdb.ListAttributionKeysParams{ExecutorID: executorID, ChainID: chainID, FromEpoch: 0, ToEpoch: 6})
		if err != nil || len(keys) != 1 || keys[0].Epoch != 5 || !bytes.Equal(keys[0].Key, final[0].Key) {
			t.Fatalf("duplicate/reordered disclosures changed final history: %d rows, %v", len(keys), err)
		}
	}
	verify(dispatcherDB, d)
	d.Close()
	if err := dispatcherDB.Close(); err != nil {
		t.Fatal(err)
	}
	dispatcherDB = open(dispatcherPath, dispatcherdb.MigrationFS())
	restarted := startDispatcher(dispatcherDB)
	if len(restarted.ListExecutors()) != 0 {
		t.Fatal("fresh dispatcher unexpectedly has a live executor")
	}
	verify(dispatcherDB, restarted)
}
