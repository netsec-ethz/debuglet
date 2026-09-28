// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func resultFixture(t *testing.T) Result {
	t.Helper()
	data, err := os.ReadFile("testdata/results/v1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ReadResult(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestResultFirstFormatFixture(t *testing.T) {
	doc := resultFixture(t)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ReadResult(bytes.NewReader(data))
	if err != nil || !reflect.DeepEqual(doc, roundTrip) {
		t.Fatalf("roundtrip: %+v, %v", roundTrip, err)
	}
	if doc.Provenance != nil || doc.Outcome.ExitCode != nil || doc.Output.Status.State != "unknown" || doc.Timing.ClockUncertaintyNS != nil {
		t.Fatal("legacy unknown facts acquired values")
	}
}

func TestResultRejectsInconsistentRecords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Result)
	}{
		{"format", func(r *Result) { r.Format = "other" }},
		{"future major", func(r *Result) { r.Version = "2.0" }},
		{"invalid run", func(r *Result) { r.RunID = "run" }},
		{"nil run", func(r *Result) { r.RunID = "00000000-0000-0000-0000-000000000000" }},
		{"blank node", func(r *Result) { r.ExecutorID = "" }},
		{"partial attempt", func(r *Result) { r.Attempt = &ControlBinding{SessionID: fixtureID} }},
		{"missing observation time", func(r *Result) { r.Timing.ObservedAt = time.Time{} }},
		{"fabricated verification", func(r *Result) { r.Verification.MeasurementTruth = "verified" }},
		{"false empty completeness", func(r *Result) {
			cursor := int64(1)
			r.Output.Status = OutputStatus{State: "complete", FinalCursor: &cursor}
		}},
		{"missing loss", func(r *Result) {
			cursor := int64(0)
			r.Output.Status = OutputStatus{State: "truncated", FinalCursor: &cursor}
		}},
		{"invalid entry", func(r *Result) { r.Output.Entries = []LogEntry{{ID: 0, Timestamp: "not-a-time"}} }},
		{"cross node provenance", func(r *Result) { setResultAdmission(r); r.Provenance.ExecutorID = "another-node" }},
		{"cross attempt provenance", func(r *Result) { setResultAdmission(r); r.Provenance.Attempt.SessionID = fixtureID }},
		{"cross run provenance", func(r *Result) {
			setResultAdmission(r)
			r.Provenance.RunID = "9a8ddf26-205a-48a4-8c93-42e384f1e611"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := resultFixture(t)
			tc.change(&doc)
			data, _ := json.Marshal(doc)
			if _, err := ReadResult(bytes.NewReader(data)); err == nil {
				t.Fatal("accepted inconsistent record")
			}
		})
	}
	for _, data := range []string{"null", "{}", "[]", "{", "{} {}"} {
		if _, err := ReadResult(strings.NewReader(data)); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
}

func TestExportSupportsFullRunAndKeepsOrdinaryResponseBound(t *testing.T) {
	doc := resultFixture(t)
	cursor := int64(1)
	doc.Output.Status = OutputStatus{State: "complete", FinalCursor: &cursor}
	doc.Output.Entries = []LogEntry{{ID: 1, Timestamp: "2026-09-28T12:00:00Z", Output: bytes.Repeat([]byte{0, 255}, 4<<20)}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeServer(t, "")
	f.handle("GET /debuglet/{id}/result", jsonHandler(http.StatusOK, string(data)))
	c := f.client(t, Options{})
	got, err := c.Export(testContext(t), fixtureID)
	if err != nil || !bytes.Equal(got.Output.Entries[0].Output, doc.Output.Entries[0].Output) {
		t.Fatalf("8 MiB output export: %v", err)
	}
	f.handle("GET /version", jsonHandler(http.StatusOK, string(data)))
	if _, err := c.Version(testContext(t)); err == nil || !strings.Contains(err.Error(), "4 MiB") {
		t.Fatalf("ordinary route bound: %v", err)
	}
	doc.RunID = "9a8ddf26-205a-48a4-8c93-42e384f1e611"
	data, _ = json.Marshal(doc)
	f.handle("GET /debuglet/{id}/result", jsonHandler(http.StatusOK, string(data)))
	if _, err := c.Export(testContext(t), fixtureID); err == nil {
		t.Fatal("accepted another run's export")
	}
}

func TestResultReaderBoundsInput(t *testing.T) {
	r := &resultPaddingReader{}
	if _, err := ReadResult(io.LimitReader(r, wire.MaxResultBytes+1024)); err == nil || !strings.Contains(err.Error(), "32 MiB") {
		t.Fatalf("oversized reader: %v", err)
	}
	if r.read != wire.MaxResultBytes+1 {
		t.Fatalf("read %d bytes", r.read)
	}
}

type resultPaddingReader struct{ read int64 }

func (r *resultPaddingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.read += int64(len(p))
	return len(p), nil
}

func setResultAdmission(r *Result) {
	r.Attempt = &ControlBinding{DispatcherIncarnation: fixtureID, SessionID: "9a8ddf26-205a-48a4-8c93-42e384f1e611"}
	r.Provenance = &wire.ResultProvenance{RunID: r.RunID, ExecutorID: r.ExecutorID, Attempt: *r.Attempt, AdmittedAt: r.Timing.ObservedAt, WorkloadSHA256: strings.Repeat("a", 64), Arguments: []string{}, AdmittedPolicy: Policy{TimeoutMS: 1}, HostPolicy: "unknown"}
	r.Verification.Attribution = "unenrolled_session"
}

func TestResultPreservesIncompleteAndAdmissionFacts(t *testing.T) {
	for _, state := range []string{"pending", "truncated", "complete"} {
		doc := resultFixture(t)
		setResultAdmission(&doc)
		doc.Output.Status.State = state
		if state != "pending" {
			final := int64(0)
			doc.Output.Status.FinalCursor = &final
		}
		if state == "truncated" {
			doc.Output.Status.LossReason = "output_limit"
		}
		data, _ := json.Marshal(doc)
		got, err := ReadResult(bytes.NewReader(data))
		if err != nil || !reflect.DeepEqual(doc, got) {
			t.Fatalf("%s: %+v, %v", state, got, err)
		}
	}
}
