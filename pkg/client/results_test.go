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
		{"1.0 exit code", func(r *Result) { code := int64(0); r.Outcome.ExitCode = &code }},
		{"1.0 start time", func(r *Result) { at := r.Timing.ObservedAt; r.Timing.StartedAt = &at }},
		{"1.0 finish time", func(r *Result) { at := r.Timing.ObservedAt; r.Timing.FinishedAt = &at }},
		{"1.0 clock bound", func(r *Result) { bound := int64(1); r.Timing.ClockUncertaintyNS = &bound }},
		{"malformed enrolled fingerprint", func(r *Result) {
			setResultAdmission(r)
			fingerprint := "sha256:" + strings.Repeat("a", 64)
			r.Provenance.CertificateSHA256 = &fingerprint
			r.Verification.Attribution = "enrolled_at_admission"
		}},
		{"enrolled fingerprint without enrolled attribution", func(r *Result) {
			setResultAdmission(r)
			fingerprint := strings.Repeat("b", 64)
			r.Provenance.CertificateSHA256 = &fingerprint
		}},
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

// An admission from an enrolled executor carries its certificate fingerprint
// and is attributed to that enrollment, not to an unenrolled session.
func TestResultAcceptsEnrolledAttribution(t *testing.T) {
	doc := resultFixture(t)
	setResultAdmission(&doc)
	fingerprint := strings.Repeat("c", 64)
	doc.Provenance.CertificateSHA256 = &fingerprint
	doc.Verification.Attribution = "enrolled_at_admission"
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadResult(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if read.Verification.Attribution != "enrolled_at_admission" || read.Provenance.CertificateSHA256 == nil || *read.Provenance.CertificateSHA256 != fingerprint {
		t.Fatalf("enrolled attribution not preserved: %+v", read)
	}
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

func currentResultFixture(t *testing.T) Result {
	t.Helper()
	data, err := os.ReadFile("testdata/results/v1.1.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ReadResult(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestResultVantagePointFixture(t *testing.T) {
	doc := currentResultFixture(t)
	v := doc.Provenance.VantagePoint
	if doc.Version != wire.ResultVersion || v == nil || v.SchemaVersion != 1 {
		t.Fatalf("vantage point: %+v", v)
	}
	if c := v.Capabilities; c.Value == nil || *c.Source != wire.SourceExecutorReported || *c.Stale || !reflect.DeepEqual(c.Value.Protocols, []string{"tcp", "udp", "icmp"}) {
		t.Fatalf("capabilities: %+v", c)
	}
	if *v.SourceIP.Source != wire.SourceDispatcherObserved || v.PublicHost.Value != nil || v.PublicHost.Source != nil {
		t.Fatalf("labels: %+v", v)
	}
	data, _ := json.Marshal(doc)
	if again, err := ReadResult(bytes.NewReader(data)); err != nil || !reflect.DeepEqual(again, doc) {
		t.Fatalf("roundtrip: %v", err)
	}
	// A 1.1 file may still describe a run admitted before vantage points.
	doc.Provenance.VantagePoint = nil
	data, _ = json.Marshal(doc)
	if _, err := ReadResult(bytes.NewReader(data)); err != nil {
		t.Fatalf("1.1 without vantage point: %v", err)
	}
}

func TestResultRejectsInvalidVantagePoint(t *testing.T) {
	label := func(s string) *string { return &s }
	for _, tc := range []struct {
		name   string
		change func(*wire.VantagePoint)
	}{
		{"future schema", func(v *wire.VantagePoint) { v.SchemaVersion = 2 }},
		{"verified label", func(v *wire.VantagePoint) { v.SourceIP.Source = label("verified") }},
		{"value without source", func(v *wire.VantagePoint) { v.SourceIP.Source = nil }},
		{"source without value", func(v *wire.VantagePoint) { v.PublicHost.Source = label(wire.SourceExecutorReported) }},
		{"blank value", func(v *wire.VantagePoint) {
			v.PublicHost = wire.LabelledString{Value: label(" "), Source: label(wire.SourceExecutorReported)}
		}},
		{"undated capabilities", func(v *wire.VantagePoint) { v.Capabilities.ObservedAt = nil }},
		{"capabilities without staleness", func(v *wire.VantagePoint) { v.Capabilities.Stale = nil }},
		{"unknown enforcement", func(v *wire.VantagePoint) { v.Capabilities.Value.EnforcementMode = "kernel" }},
		{"orphan capability source", func(v *wire.VantagePoint) { v.Capabilities.Value = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := currentResultFixture(t)
			tc.change(doc.Provenance.VantagePoint)
			data, _ := json.Marshal(doc)
			if _, err := ReadResult(bytes.NewReader(data)); err == nil {
				t.Fatal("accepted invalid vantage point")
			}
		})
	}
	// Format 1.0 has no vantage point; a 1.0 file carrying one is rejected.
	doc := currentResultFixture(t)
	doc.Version = wire.ResultVersion10
	data, _ := json.Marshal(doc)
	if _, err := ReadResult(bytes.NewReader(data)); err == nil {
		t.Fatal("accepted 1.0 file carrying vantage_point")
	}
	doc.Provenance.VantagePoint = nil
	data, _ = json.Marshal(doc)
	if _, err := ReadResult(bytes.NewReader(data)); err != nil {
		t.Fatalf("1.0 file with provenance: %v", err)
	}
}

// The capability report's tagging mode is additive within format 1.1: a file
// without it (the fixture) reads as unknown, a file with it keeps it, and a
// mode this reader does not know is kept rather than refused.
func TestResultVantagePointTagging(t *testing.T) {
	doc := currentResultFixture(t)
	if doc.Provenance.VantagePoint.Capabilities.Value.Tagging != nil {
		t.Fatal("tagging invented for a report without it")
	}
	for _, tagging := range []wire.TaggingMode{
		{IPv4: wire.TaggingEBPF, IPv6: wire.TaggingNone, SCION: wire.TaggingNone},
		{IPv4: wire.TaggingEBPF, IPv6: "destination-options", SCION: wire.TaggingNone},
	} {
		doc.Provenance.VantagePoint.Capabilities.Value.Tagging = &tagging
		data, _ := json.Marshal(doc)
		read, err := ReadResult(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%+v: %v", tagging, err)
		}
		if got := read.Provenance.VantagePoint.Capabilities.Value.Tagging; got == nil || *got != tagging {
			t.Fatalf("tagging %+v read as %+v", tagging, got)
		}
	}
}
