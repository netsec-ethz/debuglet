// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestExportRejectsExpandedJSONBeforeWriting(t *testing.T) {
	data, err := os.ReadFile("../../pkg/client/testdata/results/v1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	// JSON permits literal '<'; the CLI's encoder escapes each one as six bytes.
	data = bytes.Replace(data, []byte("fixture-executor"), bytes.Repeat([]byte("<"), 6<<20), 1)
	if len(data) >= wire.MaxResultBytes {
		t.Fatal("fixture exceeds the response limit before encoding")
	}
	if _, err := client.ReadResult(bytes.NewReader(data)); err != nil {
		t.Fatalf("alternate response must be a valid portable result: %v", err)
	}
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/debuglet/"+fixJobID+"/result" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	code, stdout, stderr := runCLI(context.Background(), "--endpoint", f.endpoint(), "export", fixJobID)
	if code != exitFailure || stdout != "" || !strings.Contains(stderr, "result exceeds 32 MiB after JSON encoding") {
		t.Fatalf("exit=%d, stdout bytes=%d, stderr=%q", code, len(stdout), stderr)
	}
}

// The CLI and the SDK read the same server response into the same record, and
// the CLI's bytes are a standalone file: the offline reader accepts them and a
// re-encoded copy reads back unchanged.
func TestExportMatchesSDKAndRoundTrips(t *testing.T) {
	data, err := os.ReadFile("../../pkg/client/testdata/results/v1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc client.Result
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	attempt := wire.ControlBinding{DispatcherIncarnation: "3f1c2b7e-9d4a-4c1e-8b6f-2a5d7e9c0b14", SessionID: "9a8ddf26-205a-48a4-8c93-42e384f1e611"}
	executorSoftware, dispatcherSoftware, fingerprint := "debuglet-executor 1.8.0", "debuglet-dispatcher 1.8.0", strings.Repeat("c", 64)
	admitted := doc.Timing.ObservedAt.Add(-time.Minute)
	reserved := admitted.Add(30 * time.Second)
	final := int64(2)
	doc.Attempt = &attempt
	doc.Provenance = &wire.ResultProvenance{
		RunID: doc.RunID, ExecutorID: doc.ExecutorID, Attempt: attempt, AdmittedAt: admitted,
		WorkloadSHA256: strings.Repeat("a", 64), Arguments: []string{"--target", "192.0.2.1"},
		AdmittedPolicy: wire.Policy{FloorBW: 1000, CeilBW: 5000, TimeoutMS: 20000, Addresses: []string{"192.0.2.1"}, RequireICMP: true},
		HostPolicy:     "unknown", ExecutorSoftware: &executorSoftware, DispatcherSoftware: &dispatcherSoftware, CertificateSHA256: &fingerprint,
	}
	doc.Outcome.State = client.StateExited
	doc.Timing.ScheduledStart, doc.Timing.ReservedUntil = &admitted, &reserved
	doc.Output.Status = wire.OutputStatus{State: "truncated", FinalCursor: &final, LossReason: "storage_limit"}
	doc.Output.Entries = []wire.LogEntry[[]byte]{
		{ID: 1, Timestamp: "2026-09-28T11:59:10Z", Output: []byte("probe 1 ok\n")},
		{ID: 2, Timestamp: "2026-09-28T11:59:20.5Z", Output: []byte{0x00, 0xff, '<', '\n'}},
	}
	doc.Verification.Attribution = "enrolled_at_admission"
	doc.Version = wire.ResultVersion
	ip, observed := wire.SourceDispatcherObserved, admitted.Add(-10*time.Second)
	fresh := false
	sourceIP := "198.51.100.7"
	reported := wire.SourceExecutorReported
	doc.Provenance.VantagePoint = &wire.VantagePoint{SchemaVersion: 1,
		Capabilities: wire.VantageCapabilities{Value: &wire.CapabilityReport{SchemaVersion: 1, Protocols: []string{"udp"}}, Source: &reported, ObservedAt: &observed, Stale: &fresh},
		SourceIP:     wire.LabelledString{Value: &sourceIP, Source: &ip},
	}
	response, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadResult(bytes.NewReader(response)); err != nil {
		t.Fatalf("fixture response must be a valid portable result: %v", err)
	}
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/debuglet/"+fixJobID+"/result" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))

	code, stdout, stderr := runCLI(context.Background(), "--endpoint", f.endpoint(), "export", fixJobID)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit=%d, stderr=%q", code, stderr)
	}
	fromCLI, err := client.ReadResult(strings.NewReader(stdout))
	if err != nil {
		t.Fatalf("CLI export is not a readable result: %v", err)
	}
	c, err := client.New(f.endpoint(), client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fromSDK, err := c.Export(context.Background(), fixJobID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromCLI, fromSDK) {
		t.Fatalf("CLI and SDK records differ:\ncli: %+v\nsdk: %+v", fromCLI, fromSDK)
	}
	if !reflect.DeepEqual(fromSDK, doc) {
		t.Fatalf("SDK record differs from the served document:\ngot:  %+v\nwant: %+v", fromSDK, doc)
	}
	if fromCLI.Format != wire.ResultFormat || fromCLI.Version != wire.ResultVersion {
		t.Fatalf("format=%q version=%q", fromCLI.Format, fromCLI.Version)
	}

	reencoded, err := json.Marshal(fromCLI)
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.ReadResult(bytes.NewReader(reencoded))
	if err != nil {
		t.Fatalf("re-encoded export is not readable: %v", err)
	}
	if !reflect.DeepEqual(again, fromCLI) {
		t.Fatalf("round trip changed the record:\ngot:  %+v\nwant: %+v", again, fromCLI)
	}
	if string(reencoded) != stdout {
		t.Fatal("re-encoding the CLI export changed its bytes")
	}
	if n := f.count(http.MethodGet, "/debuglet/"+fixJobID+"/result"); n != 2 {
		t.Fatalf("result requests = %d, want 2", n)
	}
}
