// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

// The contract fixture has no compiler socket. Exercise the authenticated
// disabled response at both supported API prefixes, with real authoring source.
func oaStudioUnavailableExchanges(t *testing.T, ctx context.Context, recorder *oaRecorder, base, token string) {
	t.Helper()
	raw := &http.Client{Transport: recorder, Timeout: ccRequestBound}
	t.Cleanup(raw.CloseIdleConnections)
	wf := communityTestWorkflow()
	experiment := workflow.Experiment{
		Version: 1, Kind: "experiment", Name: "Contract experiment",
		Participants: []workflow.Participant{{ID: "a", Workflow: wf}, {ID: "b", Workflow: wf}},
		Channels:     []workflow.Channel{},
	}
	for _, operation := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/studio/catalog", nil},
		{http.MethodPost, "/studio/validate", wf},
		{http.MethodPost, "/studio/build", wf},
		{http.MethodPost, "/studio/experiments/validate", experiment},
		{http.MethodPost, "/studio/experiments/build", experiment},
	} {
		var data []byte
		if operation.body != nil {
			var err error
			data, err = json.Marshal(operation.body)
			if err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequestWithContext(ctx, operation.method, base+operation.path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if operation.body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := raw.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s: status %d, want 503: %s", operation.path, resp.StatusCode, body)
		}
	}
}

// The public schema must describe the exact catalog produced by the shared
// workflow package, including arbitrary JSON defaults for primitive ports.
func TestContractStudioCatalog(t *testing.T) {
	c := oaContract(t)
	data, err := json.Marshal(workflow.Catalog())
	if err != nil {
		t.Fatal(err)
	}
	oaCheckResponse(t, c, http.MethodGet, "/studio/catalog", http.StatusOK, data)
}
