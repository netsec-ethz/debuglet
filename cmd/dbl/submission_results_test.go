// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestFailedRunReceiptKeepsAdmittedIdentity(t *testing.T) {
	for _, output := range []string{outputJSON, outputHuman} {
		t.Run(output, func(t *testing.T) {
			fx := newFixture(t, dispatcherMux(stateScript(state("RunStateExited", "")), nil, func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, http.StatusInternalServerError, map[string]any{
					"code": "internal_error", "message": "failed to upload admitted debuglets; inspect their state", "admitted_ids": []string{fixJobID},
				})
			}))
			code, stdout, stderr := runCLI(context.Background(), "--endpoint", fx.endpoint(), "--output", output, "run", "--wait", "--wasm", wasmFile(t), "--executor", fixExecutor)
			assertCode(t, code, exitFailure, stdout, stderr)
			if output == "json" {
				doc := oneJSONDocument(t, stdout)
				if doc["id"] != fixJobID || doc["transaction_id"] != fixTxID || doc["state"] != stateSubmissionUnknown {
					t.Fatalf("admitted receipt lost: %v", doc)
				}
			} else if !strings.Contains(stdout, "id: "+fixJobID+"\n") || !strings.Contains(stdout, "state: "+stateSubmissionUnknown+"\n") {
				t.Fatalf("admitted receipt lost: %q", stdout)
			}
			if !strings.Contains(stderr, "admitted; outcome unknown") || fx.total() != 2 {
				t.Fatalf("failed admission was replayed, polled, cancelled or misclassified: requests=%d stderr=%q", fx.total(), stderr)
			}
		})
	}
}
