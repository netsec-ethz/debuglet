// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestMeasurementBatchRetainsOriginalRequestsAndOwnership(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, _, alice := authAccount(t, f, "Alice")
	_, _, bob := authAccount(t, f, "Bob")
	ctx, cancel := f.requestCtx()
	defer cancel()
	config := sampleProfile()
	requests := []client.Request{
		{OrderID: 7, ExecutorID: ccExecutorID, Wasm: ccGuest, Args: config.Args, Policy: config.Policy, Label: "First echo", ProgramName: "echo.wasm"},
		{OrderID: 9, ExecutorID: ccExecutorID, Wasm: ccGuest, Args: []string{"second"}, Policy: config.Policy, Label: "Second echo", ProgramName: "echo.wasm"},
	}
	requests[0].Policy.Addresses = []string{"127.0.0.1:80"}
	batch, err := client.Prepare(requests)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := alice.SubmitTEST(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := alice.Measurement(ctx, submission.TransactionID)
	if err != nil || len(doc.Runs) != 2 {
		t.Fatalf("batch: %+v %v", doc, err)
	}
	for i, ref := range doc.Runs {
		run, err := alice.RunDetail(ctx, ref.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if run.RunID != submission.IDs[i] || run.BatchID != submission.TransactionID || run.OrderID != requests[i].OrderID {
			t.Fatal("lost child identity or order")
		}
		if run.Submitted == nil || !reflect.DeepEqual(run.Submitted.Args, requests[i].Args) || !reflect.DeepEqual(run.Submitted.Policy, requests[i].Policy) || run.Submitted.ProgramName != "echo.wasm" {
			t.Fatalf("original request changed: %+v", run.Submitted)
		}
		if run.Timing.StartedAt != nil || run.Timing.FinishedAt != nil || run.Cost == nil || run.Cost.Currency != "TEST" || run.Cost.Charged != nil {
			t.Fatalf("invented actual run values: %+v", run)
		}
	}
	first, err := alice.RunDetail(ctx, doc.Runs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Provenance.AdmittedPolicy.Addresses[0] != "127.0.0.1" {
		t.Fatal("fixture did not exercise normalization")
	}
	for i := int64(0); i < 3; i++ {
		page, err := alice.MeasurementRuns(ctx, submission.TransactionID, 1, i)
		if err != nil || page.Total != 2 || page.Offset != i || page.Limit != 1 {
			t.Fatalf("child page %d: %+v %v", i, page, err)
		}
		if i < 2 && (len(page.Runs) != 1 || page.Runs[0].RunID != submission.IDs[i] || page.Runs[0].Label != requests[i].Label) {
			t.Fatal("lost ordered child")
		}
		if i == 2 && len(page.Runs) != 0 {
			t.Fatal("expected empty final page")
		}
	}
	for _, operation := range []func() error{
		func() error { _, err := bob.RunDetail(ctx, submission.IDs[0]); return err },
		func() error { _, err := bob.Measurement(ctx, submission.TransactionID); return err },
	} {
		var failure *client.HTTPError
		if err := operation(); !errors.As(err, &failure) || failure.StatusCode != http.StatusNotFound {
			t.Fatalf("other account detail: %v", err)
		}
	}
	page, err := alice.Measurements(ctx, client.MeasurementOptions{Search: "echo", Limit: 1})
	if err != nil || page.Total != 1 || len(page.Measurements) != 1 || page.Measurements[0].Children != 2 || page.Counts["running"] != 1 {
		t.Fatalf("group listing: %+v %v", page, err)
	}
	other, err := bob.Measurements(ctx, client.MeasurementOptions{})
	if err != nil || other.Total != 0 {
		t.Fatalf("other account list: %+v %v", other, err)
	}
	if _, err := f.db.ExecContext(ctx, "UPDATE debuglets SET state=5, error='owned fixture failure' WHERE transaction_id=?", submission.TransactionID); err != nil {
		t.Fatal(err)
	}
	projected, err := alice.RunDetail(ctx, submission.IDs[0])
	if err != nil || projected.Outcome.Error == "owned fixture failure" || projected.Outcome.Error == "" {
		t.Fatalf("private detail error escaped projection: %+v %v", projected.Outcome, err)
	}
	page, err = alice.Measurements(ctx, client.MeasurementOptions{State: "failed"})
	if err != nil || page.Total != 1 || page.Counts["failed"] != 1 {
		t.Fatalf("failed filter: %+v %v", page, err)
	}
}

func TestMeasurementDetailDoesNotLoadOversizedOutput(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, _, alice := authAccount(t, f, "Alice")
	submission := f.submit(alice, []string{"retained args"})
	ctx, cancel := f.requestCtx()
	defer cancel()
	if _, err := f.db.ExecContext(ctx, "INSERT INTO debuglet_logs(debuglet_id,timestamp,output) SELECT id,CURRENT_TIMESTAMP,? FROM debuglets WHERE uuid=?", bytes.Repeat([]byte("a"), 25<<20), submission.IDs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Export(ctx, submission.IDs[0]); err == nil {
		t.Fatal("fixture export should exceed the output limit")
	}
	detail, err := alice.RunDetail(ctx, submission.IDs[0])
	if err != nil || detail.Submitted == nil || !reflect.DeepEqual(detail.Submitted.Args, []string{"retained args"}) {
		t.Fatalf("detail depends on output: %+v %v", detail, err)
	}
}

func TestMeasurementDetailRetainsHistoricalConfigurationBeyondProfileLimit(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, _, alice := authAccount(t, f, "Alice")
	submission := f.submit(alice, []string{"original"})
	ctx, cancel := f.requestCtx()
	defer cancel()
	detail, err := alice.RunDetail(ctx, submission.IDs[0])
	if err != nil {
		t.Fatal(err)
	}
	// Seed an admission predating the new 256 KiB configuration limit. Its
	// retained provenance remains immutable through the public API.
	seed := func(size int) {
		t.Helper()
		detail.Provenance.Arguments = []string{strings.Repeat("h", size)}
		encoded, err := json.Marshal(detail.Provenance)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for _, query := range []string{"DELETE FROM measurement_requests WHERE debuglet_id=(SELECT id FROM debuglets WHERE uuid=?)", "DELETE FROM debuglet_provenance WHERE debuglet_id=(SELECT id FROM debuglets WHERE uuid=?)"} {
			if _, err := tx.ExecContext(ctx, query, submission.IDs[0]); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO debuglet_provenance(debuglet_id,document) SELECT id,? FROM debuglets WHERE uuid=?", encoded, submission.IDs[0]); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	seed(9 << 20)
	retained, err := alice.RunDetail(ctx, submission.IDs[0])
	if err != nil || retained.Submitted != nil || retained.Provenance == nil || len(retained.Provenance.Arguments) != 1 || retained.Provenance.Arguments[0] != detail.Provenance.Arguments[0] {
		t.Fatalf("historical detail: %v", err)
	}
	seed(33 << 20)
	_, err = alice.RunDetail(ctx, submission.IDs[0])
	var response *client.HTTPError
	if !errors.As(err, &response) || response.StatusCode != http.StatusRequestEntityTooLarge || response.Code != CodePayloadTooLarge {
		t.Fatalf("oversized historical detail: %v", err)
	}
}
