// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func experimentDefinition(t *testing.T) ExperimentDefinition {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peer.wasm")
	if err := os.WriteFile(path, []byte("test-wasm"), 0600); err != nil {
		t.Fatal(err)
	}
	return ExperimentDefinition{Participants: []ExperimentRun{
		{OrderID: 42, ExecutorID: "node-a", WASMPath: path, Args: []string{"a"}, Policy: Policy{TimeoutMS: 1000}},
		{OrderID: 7, ExecutorID: "node-b", WASMPath: path, Args: []string{"b"}, Policy: Policy{TimeoutMS: 2000}},
	}}
}

func TestExperimentRetainsManifestOrderAndHashes(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("PUT /payment/intent", intentHandler(fixtureTx, ""))
	ids := []string{fixtureID, "00000000-0000-4000-8000-000000000002"}
	body, _ := json.Marshal(ids)
	f.handle("PUT /debuglet", jsonHandler(http.StatusOK, string(body)))
	definition := experimentDefinition(t)
	receipt, err := f.client(t, Options{}).SubmitExperimentTEST(t.Context(), definition)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("test-wasm"))
	if receipt.ExperimentID != fixtureTx || receipt.Participants[0].OrderID != 42 || receipt.Participants[1].OrderID != 7 || receipt.Participants[0].RunID != ids[0] || receipt.Participants[1].RunID != ids[1] || receipt.Participants[0].SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("receipt %+v", receipt)
	}
	definition.Participants[0].Args[0] = "changed"
	if receipt.Participants[0].Args[0] != "a" || definition.Participants[0].SHA256 != "" {
		t.Fatal("receipt aliases or mutates caller input")
	}
	if len(f.requests()) != 2 {
		t.Fatal("submission made unexpected requests")
	}
}

func TestExperimentRejectsChangedWASMBeforeSubmission(t *testing.T) {
	f := newFakeServer(t, "")
	definition := experimentDefinition(t)
	definition.Participants[1].SHA256 = strings.Repeat("0", 64)
	_, err := f.client(t, Options{}).SubmitExperimentTEST(t.Context(), definition)
	if err == nil || len(f.requests()) != 0 {
		t.Fatal("changed artifact reached dispatcher")
	}
}

func TestExperimentPreservesUncertainAdmission(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("PUT /payment/intent", intentHandler(fixtureTx, ""))
	ids := []string{fixtureID, "00000000-0000-4000-8000-000000000002"}
	body, _ := json.Marshal(map[string]any{"code": CodeInternal, "message": "failed", "admitted_ids": ids})
	f.handle("PUT /debuglet", jsonHandler(http.StatusInternalServerError, string(body)))
	receipt, err := f.client(t, Options{}).SubmitExperimentTEST(t.Context(), experimentDefinition(t))
	se := asSubmissionError(t, err)
	if !se.OutcomeUnknown || receipt.ExperimentID != fixtureTx || !reflect.DeepEqual([]string{receipt.Participants[0].RunID, receipt.Participants[1].RunID}, ids) {
		t.Fatalf("receipt %+v error %v", receipt, err)
	}
}

func TestExperimentExportRejectsWrongExecutor(t *testing.T) {
	f := newFakeServer(t, "")
	doc := resultFixture(t)
	body, _ := json.Marshal(RunDetail{RunID: doc.RunID, ExecutorID: doc.ExecutorID, BatchID: fixtureTx})
	f.handle("GET /debuglet/"+doc.RunID+"/detail", jsonHandler(http.StatusOK, string(body)))
	receipt := ExperimentSubmission{ExperimentID: fixtureTx, Participants: []ExperimentRun{{RunID: doc.RunID, ExecutorID: "wrong-executor"}}}
	result, err := f.client(t, Options{}).ExportExperiment(t.Context(), receipt)
	if err == nil || len(result.Results) != 0 {
		t.Fatal("mismatched result was grouped")
	}
}

func TestExperimentActionsRejectWrongBatchBeforeReadingOrCancelling(t *testing.T) {
	for _, action := range []string{"export", "cancel"} {
		t.Run(action, func(t *testing.T) {
			f := newFakeServer(t, "")
			doc := resultFixture(t)
			receipt := ExperimentSubmission{ExperimentID: fixtureTx, Participants: []ExperimentRun{
				{RunID: doc.RunID, OrderID: 42, ExecutorID: doc.ExecutorID},
				{RunID: "00000000-0000-4000-8000-000000000002", OrderID: 7, ExecutorID: doc.ExecutorID},
			}}
			// The first run matches. The later run belongs to another batch,
			// so even cancellation of the first run must not begin.
			for i, participant := range receipt.Participants {
				batch := fixtureTx
				if i == 1 {
					batch = "another-transaction"
				}
				detail := RunDetail{RunID: participant.RunID, ExecutorID: participant.ExecutorID, BatchID: batch, OrderID: participant.OrderID}
				body, _ := json.Marshal(detail)
				f.handle("GET /debuglet/"+participant.RunID+"/detail", jsonHandler(http.StatusOK, string(body)))
			}
			c := f.client(t, Options{})
			var err error
			if action == "export" {
				var group ExperimentResults
				group, err = c.ExportExperiment(t.Context(), receipt)
				if len(group.Results) != 0 {
					t.Fatal("mismatched batch returned grouped results")
				}
			} else {
				err = c.CancelExperiment(t.Context(), receipt)
			}
			if err == nil || len(f.requests()) != 2 {
				t.Fatalf("action=%s error=%v requests=%d", action, err, len(f.requests()))
			}
		})
	}
}

func TestExperimentRejectsOversizedMembershipBeforeReadingFiles(t *testing.T) {
	f := newFakeServer(t, "")
	definition := ExperimentDefinition{Participants: make([]ExperimentRun, wire.MaxExperimentParticipants+1)}
	// Every path is empty: a file read would fail with a different error.
	_, err := f.client(t, Options{}).SubmitExperimentTEST(t.Context(), definition)
	if err == nil || !strings.Contains(err.Error(), "exceeds 128 participants") || len(f.requests()) != 0 {
		t.Fatalf("error=%v requests=%d", err, len(f.requests()))
	}
}
