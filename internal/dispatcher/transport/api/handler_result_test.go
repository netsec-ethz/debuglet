// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"go.uber.org/zap"
)

func TestResultExportPreservesAdmissionAndIncompleteOutput(t *testing.T) {
	f := ccNewFixture(t)
	f.dbl = ccBuildCLI(t)
	c := f.client(f.root.URL, false)
	args := []string{"target.example:443", "argument with spaces", "a,b", ""}
	sub := f.submit(c, args)
	ids := f.seedLogs(sub.IDs[0], [][]byte{{0, 255, 10}, []byte("retained")})
	id := uuid.MustParse(sub.IDs[0])
	_, err := f.db.ExecContext(f.ctx, "UPDATE debuglet_output SET status = 'truncated', reason = 'storage_limit', last_log_id = ?, final_cursor = ?, final_sequence = committed_sequence WHERE debuglet_id = (SELECT id FROM debuglets WHERE uuid = ?)", ids[1], ids[1], id)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := c.Export(f.ctx, sub.IDs[0])
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(ccGuest)
	if doc.Provenance == nil || doc.Provenance.WorkloadSHA256 != hex.EncodeToString(hash[:]) || !reflect.DeepEqual(doc.Provenance.Arguments, args) || doc.Provenance.AdmittedPolicy.FloorBW != ccFloorBW || doc.Provenance.ExecutorSoftware == nil || *doc.Provenance.ExecutorSoftware != "client-peer" {
		t.Fatalf("provenance: %+v", doc.Provenance)
	}
	if doc.Attempt == nil || *doc.Attempt != doc.Provenance.Attempt || doc.Provenance.RunID != doc.RunID || doc.Provenance.ExecutorID != doc.ExecutorID {
		t.Fatal("attempt identity changed")
	}
	if doc.Outcome.State == client.StateExited || doc.Outcome.ExitCode != nil || doc.Output.Status.State != "truncated" || doc.Output.Status.LossReason != "storage_limit" || doc.Timing.StartedAt != nil || doc.Timing.FinishedAt != nil || doc.Timing.ClockUncertaintyNS != nil || doc.Provenance.HostPolicy != "unknown" || doc.Verification.MeasurementTruth != "unverified" {
		t.Fatalf("result invented finality or verification: %+v", doc)
	}
	code, stdout, stderr := f.runCLI("--endpoint", f.root.URL, "export", sub.IDs[0])
	if code != 0 {
		t.Fatalf("export exit%d: %s", code, stderr)
	}
	fromCLI, err := client.ReadResult(bytes.NewReader(stdout))
	if err != nil {
		t.Fatal(err)
	}
	// These are two snapshots; only their observation times differ.
	fromCLI.Timing.ObservedAt = doc.Timing.ObservedAt
	if !reflect.DeepEqual(fromCLI, doc) {
		t.Fatalf("SDK/CLI mismatch: %+v / %+v", doc, fromCLI)
	}
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglet_provenance SET document='{}' WHERE debuglet_id=(SELECT id FROM debuglets WHERE uuid=?)", id); err == nil {
		t.Fatal("admission facts rewritten")
	}
	if _, err := f.db.ExecContext(f.ctx, "DELETE FROM debuglet_provenance WHERE debuglet_id=(SELECT id FROM debuglets WHERE uuid=?)", id); err != nil {
		t.Fatal(err)
	}
	legacy, err := c.Export(f.ctx, sub.IDs[0])
	if err != nil || legacy.Provenance != nil || legacy.Verification.Attribution != "unknown" {
		t.Fatalf("legacy provenance invented: %+v, %v", legacy, err)
	}
}

func TestResultExportBoundsAndOwnership(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, _, owner := authAccount(t, f, "result owner")
	_, _, other := authAccount(t, f, "other owner")
	sub := f.submit(owner, nil)
	for _, c := range []*client.Client{other, f.client(f.root.URL, false)} {
		_, err := c.Export(f.ctx, sub.IDs[0])
		var httpErr *client.HTTPError
		if !errors.As(err, &httpErr) || (httpErr.StatusCode != http.StatusNotFound && httpErr.StatusCode != http.StatusUnauthorized) {
			t.Fatalf("ownership: %v", err)
		}
	}
	data := bytes.Repeat([]byte{0, 255}, 4<<20)
	f.seedLogs(sub.IDs[0], [][]byte{data})
	doc, err := owner.Export(f.ctx, sub.IDs[0])
	if err != nil || len(doc.Output.Entries) != 1 || !bytes.Equal(doc.Output.Entries[0].Output, data) {
		t.Fatalf("8MiB export: %v", err)
	}
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglet_logs SET output=zeroblob(?) WHERE debuglet_id=(SELECT id FROM debuglets WHERE uuid=?)", 25<<20, uuid.MustParse(sub.IDs[0])); err != nil {
		t.Fatal(err)
	}
	_, err = owner.Export(f.ctx, sub.IDs[0])
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusRequestEntityTooLarge || httpErr.Code != CodePayloadTooLarge {
		t.Fatalf("oversized export: %v", err)
	}
}

func TestResultAdmissionRollsBackOnCapacityRefusal(t *testing.T) {
	// Node and account caps are opt-in; this operator set a node cap.
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}
	f := ccNewFixtureConfigured(t, zap.NewNop(), peer, func(d *dispatcher.Dispatcher) error {
		limits := config.DefaultOutputConfig()
		limits.NodeBytes = 1 << 30
		return d.ConfigureOutputLimits(limits)
	}, LocalDevelopment(true))
	if _, err := f.db.ExecContext(f.ctx, "UPDATE output_node_usage SET charged_bytes = ? WHERE singleton = 1", int64(1)<<40); err != nil {
		t.Fatal(err)
	}
	batch, err := client.Prepare([]client.Request{ccRequest(nil)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.client(f.root.URL, false).SubmitTEST(f.ctx, batch)
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("capacity refusal: %v", err)
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM debuglet_provenance").Scan(&count); err != nil || count != 0 {
		t.Fatalf("refused admission retained %d provenance records: %v", count, err)
	}
}
