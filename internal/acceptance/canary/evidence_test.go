//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestDecodeReceipt(t *testing.T) {
	for _, want := range []RunReceipt{
		{ExecutorID: "executor", State: "submission_unknown", TransactionID: "opaque-transaction"},
		{ExecutorID: "executor", State: "submission_failed", TransactionID: "opaque-transaction"},
		{ExecutorID: "executor", State: "submitted", TransactionID: "transaction", ID: "run"},
		{ExecutorID: "executor", State: "RunStateExited", TransactionID: "transaction", ID: "run", Error: "workload failed"},
		// Semantic validation belongs to Run. The decoder preserves the fields
		// so that an invalid state/ID cannot be mistaken for an absent receipt.
		{ExecutorID: "", State: "unknown", ID: "not-a-uuid"},
	} {
		data, _ := json.Marshal(want)
		got, err := DecodeReceipt(data)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("receipt changed: got=%+v want=%+v error=%v", got, want, err)
		}
	}
	base := []byte(`{"executor_id":"executor","state":"submission_unknown"}`)
	exact := append(base, bytes.Repeat([]byte(" "), receiptSizeLimit-len(base))...)
	if _, err := DecodeReceipt(exact); err != nil {
		t.Fatalf("exact 4 MiB receipt rejected: %v", err)
	}
	if got, err := DecodeReceipt(append(exact, ' ')); err == nil || got != (RunReceipt{}) {
		t.Fatalf("oversized receipt accepted: %+v %v", got, err)
	}
	for name, data := range map[string]string{
		"empty": "", "null": "null", "array": "[]", "trailing": string(base) + "{}", "junk": string(base) + "private-secret",
		"unknown":           `{"executor_id":"executor","state":"submitted","auth_key":"private-secret"}`,
		"duplicate":         `{"executor_id":"executor","state":"submitted","state":"private-secret"}`,
		"escaped_duplicate": `{"executor_id":"executor","state":"submitted","\u0073tate":"private-secret"}`,
		"alias":             `{"Executor_ID":"executor","state":"submitted"}`,
		"null_required":     `{"executor_id":null,"state":"submitted"}`,
		"missing_executor":  `{"state":"submitted"}`,
		"missing_state":     `{"executor_id":"executor"}`,
		"wrong_type":        `{"executor_id":"executor","state":42}`,
		"invalid_utf8":      "{\"executor_id\":\"executor\",\"state\":\"private-secret\xff\"}",
	} {
		t.Run(name, func(t *testing.T) { assertReceiptRejected(t, []byte(data)) })
	}
	for _, key := range []string{"id", "transaction_id", "error", "executor_id", "state"} {
		t.Run(key+"_null", func(t *testing.T) {
			fields := map[string]any{"executor_id": "executor", "state": "submitted", key: nil}
			data, _ := json.Marshal(fields)
			assertReceiptRejected(t, data)
		})
	}
}

func assertReceiptRejected(t *testing.T, data []byte) {
	t.Helper()
	got, err := DecodeReceipt(data)
	if err == nil || got != (RunReceipt{}) || strings.Contains(err.Error(), "private-secret") {
		t.Fatalf("receipt not safely rejected: %+v %v", got, err)
	}
}

func evidenceFixture() Evidence {
	return Evidence{SchemaVersion: 1, Environment: "local", ETHTestbed: "unconfirmed", Outcome: "failed", Phase: "startup", SourceSHA: strings.Repeat("a", 40), ArchiveSHA256: strings.Repeat("b", 64), ManifestSHA256: strings.Repeat("c", 64), ExecutorID: manifestFixture().ExecutorID, StartedAt: "2026-09-09T00:00:00Z"}
}

func privateEvidenceDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private evidence directory")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWriteEvidence(t *testing.T) {
	dir := privateEvidenceDir(t)
	want := evidenceFixture()
	if err := WriteEvidence(dir, want); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "result.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("result mode: %v %v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Evidence
	if err := json.Unmarshal(data, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence changed: %+v %v", got, err)
	}
	for _, fragment := range []string{`"submission":null`, `"run_id":null`, `"output_marker_seen":null`, `"ack":null`, `"registry_ineligible":null`, `"children_reaped":null`, `"forced_kills":null`, `"finished_at":null`, `"error":null`} {
		if !bytes.Contains(data, []byte(fragment)) {
			t.Fatalf("unobserved value fabricated: missing %s", fragment)
		}
	}
	if err := WriteEvidence(dir, Evidence{Outcome: "passed"}); err == nil {
		t.Fatal("existing result overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("existing result changed")
	}
	assertOnlyResult(t, dir)
}

func TestEvidenceObservedValues(t *testing.T) {
	dir := privateEvidenceDir(t)
	e := evidenceFixture()
	f := false
	zero := 0
	empty := ""
	tx := "transaction"
	e.Submission = &SubmissionEvidence{State: "submission_unknown", TransactionID: &tx, OutcomeUnknown: true}
	e.Target.ACK = &f
	e.Terminal.Error = &empty
	e.Cleanup.ForcedKills = &zero
	e.OutputMarkerSeen = &f
	if err := WriteEvidence(dir, e); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got Evidence
	if err := json.Unmarshal(data, &got); err != nil || !reflect.DeepEqual(e, got) {
		t.Fatalf("known values lost: %+v %v", got, err)
	}
}

func assertOnlyResult(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "result.json" {
		t.Fatalf("unexpected publication leftovers: %v %v", entries, err)
	}
}

func TestEvidenceRefusesUnsafePaths(t *testing.T) {
	for _, name := range []string{"missing", "public_mode", "directory_symlink", "file_result", "symlink_result", "directory_result"} {
		t.Run(name, func(t *testing.T) {
			dir := privateEvidenceDir(t)
			sentinel := filepath.Join(t.TempDir(), "sentinel")
			if err := os.WriteFile(sentinel, []byte("preserved"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "result.json")
			switch name {
			case "missing":
				dir = filepath.Join(dir, "absent")
			case "public_mode":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory_symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			case "file_result":
				if err := os.WriteFile(path, []byte("preserved"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink_result":
				if err := os.Symlink(sentinel, path); err != nil {
					t.Fatal(err)
				}
			case "directory_result":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := WriteEvidence(dir, evidenceFixture()); err == nil {
				t.Fatal("unsafe evidence path accepted")
			}
			data, err := os.ReadFile(sentinel)
			if err != nil || string(data) != "preserved" {
				t.Fatal("unrelated sentinel changed")
			}
			if name == "missing" {
				if _, err := os.Lstat(dir); !os.IsNotExist(err) {
					t.Fatal("missing directory created")
				}
			} else {
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".result-") {
						t.Fatal("owned temporary file leaked")
					}
				}
			}
			if name == "file_result" {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "preserved" {
					t.Fatal("existing result overwritten")
				}
			}
		})
	}
	if os.Geteuid() == 0 {
		t.Run("foreign_owner", func(t *testing.T) {
			dir := privateEvidenceDir(t)
			if err := os.Chown(dir, 1, -1); err != nil {
				t.Fatal(err)
			}
			if err := WriteEvidence(dir, evidenceFixture()); err == nil {
				t.Fatal("foreign directory accepted")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("foreign directory changed: %v %v", entries, err)
			}
		})
	}
}

func TestEvidenceConcurrentPublication(t *testing.T) {
	dir := privateEvidenceDir(t)
	const writers = 16
	start := make(chan struct{})
	results := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Go(func() { <-start; results <- WriteEvidence(dir, evidenceFixture()) })
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("exclusive publication successes=%d", successes)
	}
	assertOnlyResult(t, dir)
	data, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got Evidence
	if err := json.Unmarshal(data, &got); err != nil || !reflect.DeepEqual(got, evidenceFixture()) {
		t.Fatalf("partial or incorrect publication: %+v %v", got, err)
	}
}

func TestEvidenceBoundedEncoding(t *testing.T) {
	dir := privateEvidenceDir(t)
	e := evidenceFixture()
	large := strings.Repeat("x", receiptSizeLimit)
	e.Error = &large
	if err := WriteEvidence(dir, e); err == nil {
		t.Fatal("unbounded evidence accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("encoding failure created output: %v %v", entries, err)
	}
}
