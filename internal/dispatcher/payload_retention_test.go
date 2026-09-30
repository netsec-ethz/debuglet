// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/protobuf/proto"
)

func TestPayloadDeletionKeepsReferencesAndFinalReceiptAcrossRestart(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	q := database.New(d.db)
	writer := outputTestWriter()
	id := outputTestRun(t, d, writer, nil)
	sibling := outputTestRun(t, d, writer, nil)
	requireOutputReceipt(t, d, writer, id, outputFrame(1, "payload sentinel"), nil)
	requireOutputReceipt(t, d, writer, sibling, outputFrame(1, "sibling payload"), nil)
	end := &pb.DebugletOutputEnd{LastSequence: 1, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE}
	final := requireOutputReceipt(t, d, writer, id, nil, end)
	row, err := q.GetDebugletByUUID(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.db.Exec("UPDATE debuglets SET state=?,addresses=?,error=? WHERE id=?", models.RunStateExited, "private.example:443", "private stack sentinel", row.ID); err != nil {
		t.Fatal(err)
	}
	if err = q.ReserveAccountRun(t.Context(), database.ReserveAccountRunParams{DebugletID: row.ID, QueuedBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.RetireAccountRun(t.Context(), database.RetireAccountRunParams{DebugletID: row.ID, RetiredAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.db.Exec(`INSERT INTO debuglet_provenance(debuglet_id,document) VALUES(?,?)`, row.ID, `{"workload_sha256":"workload-digest","certificate_sha256":"certificate-digest","arguments":["private arg"]}`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.db.Exec(`INSERT INTO measurement_requests(debuglet_id,document) VALUES(?,?)`, row.ID, `{"args":["private arg"]}`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.db.Exec("INSERT INTO measurement_execution(debuglet_id,started_observed_ns,terminal_observed_ns,exit_code,tcp_endpoint) VALUES(?,1,2,7,'private.example:9000')", row.ID); err != nil {
		t.Fatal(err)
	}
	before, err := q.GetOutputNodeUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = d.DeleteCompletedPayload(t.Context(), id, false); err != nil {
			t.Fatal(err)
		}
	}
	observed, err := q.GetMeasurementExecution(t.Context(), row.ID)
	if err != nil || observed.TcpEndpoint != "" || observed.StartedObservedNs.Int64 != 1 || observed.TerminalObservedNs.Int64 != 2 || observed.ExitCode.Int64 != 7 {
		t.Fatalf("retained execution: %+v %v", observed, err)
	}
	after, err := q.GetOutputNodeUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	wantCharge := int64(len("payload sentinel")) + pb.OutputFrameCharge + pb.OutputRunCharge
	if before.ChargedBytes-after.ChargedBytes != wantCharge || before.FrameCount-after.FrameCount != 1 {
		t.Fatalf("charge: before=%+v after=%+v", before, after)
	}
	tombstone, err := q.GetPayloadTombstone(t.Context(), id)
	if err != nil || tombstone.WorkloadSha256.String != "workload-digest" || tombstone.CertificateSha256.String != "certificate-digest" {
		t.Fatalf("tombstone: %+v %v", tombstone, err)
	}
	for _, table := range []string{"debuglet_logs", "debuglet_provenance", "measurement_requests"} {
		var n int
		if err = d.db.QueryRow("SELECT count(*) FROM "+table+" WHERE debuglet_id=?", row.ID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: %d %v", table, n, err)
		}
	}
	retained, err := q.GetDebugletByUUID(t.Context(), id)
	if err != nil || retained.State != models.RunStateExited || retained.TransactionID != row.TransactionID || len(retained.Addresses) != 0 || retained.Error.String != PublicTerminalError("private stack sentinel") {
		t.Fatalf("references: %+v %v", retained, err)
	}
	if _, err = d.db.Exec("UPDATE payload_tombstones SET reason='retention_expired' WHERE debuglet_id=?", row.ID); err == nil {
		t.Fatal("tombstone changed")
	}
	// The reopened connection reads persisted usage; no startup reconstructs
	// charges from historical counters retained only for duplicate receipts.
	var n int
	var name, path string
	if err = d.db.QueryRow("PRAGMA database_list").Scan(&n, &name, &path); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := New(d.logger, reopened, "restart", time.Minute, time.Minute, d.Payment)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err = restarted.DeleteCompletedPayload(t.Context(), id, false); err != nil {
		t.Fatal(err)
	}
	replay := requireOutputReceipt(t, restarted, writer, id, outputFrame(1, "discarded duplicate"), nil)
	if !proto.Equal(final, replay) {
		t.Fatalf("receipt changed: %v / %v", final, replay)
	}
	if !proto.Equal(final, requireOutputReceipt(t, restarted, writer, id, nil, end)) {
		t.Fatal("end replay changed")
	}
	usage, err := database.New(reopened).GetOutputNodeUsage(t.Context())
	if err != nil || usage != after {
		t.Fatalf("recharged on restart: %+v %v", usage, err)
	}
	logs, err := q.ListDebugletLogs(t.Context(), database.ListDebugletLogsParams{Uuid: sibling, Limit: 10})
	if err != nil || len(logs) != 1 || string(logs[0].Output) != "sibling payload" {
		t.Fatalf("sibling: %+v %v", logs, err)
	}
}

func TestPayloadExpiryRequiresConfiguredAgeAndCompletedOutput(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	writer := outputTestWriter()
	q := database.New(d.db)
	id := outputTestRun(t, d, writer, nil)
	row, err := q.GetDebugletByUUID(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.db.Exec("UPDATE debuglets SET state=? WHERE id=?", models.RunStateExited, row.ID); err != nil {
		t.Fatal(err)
	}
	if err = q.ReserveAccountRun(t.Context(), database.ReserveAccountRunParams{DebugletID: row.ID, QueuedBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.RetireAccountRun(t.Context(), database.RetireAccountRunParams{DebugletID: row.ID, RetiredAt: sql.NullInt64{Int64: time.Now().Add(-time.Hour).Unix(), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	if err = d.DeleteCompletedPayload(t.Context(), id, false); !errors.Is(err, ErrPayloadNotDeletable) {
		t.Fatalf("pending output deleted: %v", err)
	}
	requireOutputReceipt(t, d, writer, id, nil, &pb.DebugletOutputEnd{Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE})
	d.sweepPayloadRetention()
	if _, err = q.GetPayloadTombstone(t.Context(), id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("default expired: %v", err)
	}
	d.retention.PayloadMaxAgeSeconds = 60
	d.sweepPayloadRetention()
	tombstone, err := q.GetPayloadTombstone(t.Context(), id)
	if err != nil || tombstone.Reason != "retention_expired" {
		t.Fatalf("expiry: %+v %v", tombstone, err)
	}
}

func TestPayloadDeletionWithoutHistoricalOutputMetadataIsNotDeletable(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	q := database.New(d.db)
	id := outputTestRun(t, d, outputTestWriter(), nil)
	run, err := q.GetDebugletByUUID(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.db.Exec("UPDATE debuglets SET state=?,addresses=? WHERE id=?", models.RunStateExited, "retained.example:443", run.ID); err != nil {
		t.Fatal(err)
	}
	if err = q.ReserveAccountRun(t.Context(), database.ReserveAccountRunParams{DebugletID: run.ID, QueuedBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.RetireAccountRun(t.Context(), database.RetireAccountRunParams{DebugletID: run.ID, RetiredAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	// Migration 10 leaves runs without sequenced-output evidence unbackfilled.
	if _, err = d.db.Exec("DELETE FROM debuglet_output WHERE debuglet_id=?", run.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.DeleteCompletedPayload(t.Context(), id, false); !errors.Is(err, ErrPayloadNotDeletable) {
		t.Fatalf("missing historical finality must refuse deletion: %v", err)
	}
	if _, err = q.GetPayloadTombstone(t.Context(), id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("refused deletion created a tombstone: %v", err)
	}
	if _, err = q.GetDebugletOutput(t.Context(), id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("refused deletion invented output metadata: %v", err)
	}
	retained, err := q.GetDebugletByUUID(t.Context(), id)
	if err != nil || retained.State != models.RunStateExited || len(retained.Addresses) != 1 || retained.Addresses[0] != "retained.example:443" {
		t.Fatalf("refused deletion changed retained payload: %+v %v", retained, err)
	}
}

func TestDispatcherOutputHeadroomKeepsFinalityAndSibling(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	d.outputLimits.ControlReserveBytes = 4096
	writer := outputTestWriter()
	q := database.New(d.db)
	id := outputTestRun(t, d, writer, nil)
	sibling := outputTestRun(t, d, writer, nil)
	requireOutputReceipt(t, d, writer, id, outputFrame(1, "prefix"), nil)
	var pages int64
	if err := d.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages+22)); err != nil {
		t.Fatal(err)
	}
	before, err := q.GetOutputNodeUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	receipt := requireOutputReceipt(t, d, writer, id, outputFrame(2, strings.Repeat("x", pb.MaxOutputFrameBytes)), nil)
	if receipt.End == nil || receipt.End.Reason != pb.OutputReasonStorageLimit || receipt.CommittedSequence != 1 {
		t.Fatalf("storage refusal: %v", receipt)
	}
	after, err := q.GetOutputNodeUsage(t.Context())
	if err != nil || before != after {
		t.Fatalf("refused charge: %+v %+v %v", before, after, err)
	}
	requireOutputReceipt(t, d, writer, sibling, outputFrame(1, "small"), nil)
	requireOutputReceipt(t, d, writer, sibling, nil, &pb.DebugletOutputEnd{LastSequence: 1, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE})
}
