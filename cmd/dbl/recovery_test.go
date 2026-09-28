// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestRecoveryCommandIsOneSuccessfulQuotedInspection(t *testing.T) {
	doc := client.RecoveryDocument{ID: fixJobID, ExecutorID: "executor\n\x1b[31m", State: "future_state", Error: "failed\n\x1b[31m", CheckedAt: time.Now().UTC(), ControlStatus: "legacy", Observation: client.RecoveryObservation{Classification: "future_unknown"}}
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSONResponse(w, http.StatusOK, doc) }))
	for _, output := range []string{outputHuman, outputJSON} {
		var out, errOut bytes.Buffer
		before := f.total()
		code := recoveryCommand(t.Context(), []string{fixJobID}, globalOptions{Endpoint: f.endpoint(), EndpointSet: true, Output: output}, &out, &errOut)
		if code != exitOK || errOut.Len() != 0 || f.total() != before+1 {
			t.Fatalf("code=%d stdout=%s stderr=%s requests=%d", code, out.String(), errOut.String(), f.total()-before)
		}
		if output == outputJSON {
			var got map[string]any
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			observation := got["observation"].(map[string]any)
			if value, present := observation["observer"]; !present || value != nil {
				t.Fatalf("missing null provenance: %v", observation)
			}
		} else if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), `executor\n\x1b[31m`) || !strings.Contains(out.String(), "does not authorize replay") {
			t.Fatalf("unsafe or misleading output: %q", out.String())
		}
	}
}

func TestRecoveryCommandPreservesFailureExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{{"http", exitFailure}, {"timeout", exitDeadline}, {"interrupt", exitInterrupted}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.name == "http" {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				<-r.Context().Done()
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if tc.name == "interrupt" {
				cancel()
			}
			var out, errOut bytes.Buffer
			code := recoveryCommand(ctx, []string{fixJobID}, globalOptions{Endpoint: f.endpoint(), EndpointSet: true, Output: outputJSON}, &out, &errOut)
			if code != tc.code || out.Len() != 0 {
				t.Fatalf("code=%d want=%d stdout=%s stderr=%s", code, tc.code, out.String(), errOut.String())
			}
		})
	}
}
