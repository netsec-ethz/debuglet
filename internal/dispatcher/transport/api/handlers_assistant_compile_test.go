// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/studio"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func TestAssistantCustomCodeCompilesAndRepairsThroughWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("WASI compilation")
	}
	sdk, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	builder, err := studio.NewBuilder(sdk)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"workflow", "experiment"} {
		t.Run(kind, func(t *testing.T) {
			var calls, builds atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				code := `return map[string]any{"value": missingIdentifier}, nil`
				if calls.Add(1) == 2 {
					body, _ := io.ReadAll(r.Body)
					if !bytes.Contains(body, []byte("undefined: missingIdentifier")) {
						t.Error("compiler error was not sent to correction")
					}
					code = `return map[string]any{"value": float64(42)}, nil`
				}
				wf := workflow.Workflow{Version: 1, Name: "Custom calculation", Entry: "calculate", Nodes: []workflow.Node{{ID: "calculate", Block: "calculation"}}, Edges: []workflow.Edge{},
					CustomBlocks: []workflow.CustomBlock{{ID: "calculation", Label: "Calculate", Outputs: []workflow.Port{{Name: "value", Type: "number"}}, Code: code}}}
				var document any = wf
				if kind == "experiment" {
					document = workflow.Experiment{Version: 1, Kind: kind, Name: "Pair", Participants: []workflow.Participant{{ID: "A", Workflow: wf}, {ID: "B", Workflow: wf}}}
				}
				proposal, _ := json.Marshal(map[string]any{"message": "Calculation", "document": document})
				studioJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "proposal", "type": "function", "function": map[string]any{"name": "propose_document", "arguments": string(proposal)}}}}}}})
			}))
			defer provider.Close()
			assistant, err := studio.NewAssistant(studio.AssistantConfig{Endpoint: provider.URL, Model: "fixture", APIKey: "fixture-secret"})
			if err != nil {
				t.Fatal(err)
			}
			worker := studio.NewWorkerHandler(builder)
			f := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				builds.Add(1)
				wantPath := "/studio/build"
				if kind == "experiment" {
					wantPath = "/studio/experiments/build"
				}
				if r.URL.Path != wantPath || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get(csrfHeaderName) != "" {
					t.Error("wrong worker route or leaked credentials")
				}
				worker.ServeHTTP(w, r)
			}), Assistant(assistant))
			input := assistantBody(t)
			if kind == "experiment" {
				doc := workflow.Experiment{Version: 1, Kind: kind, Name: "Pair", Participants: []workflow.Participant{{ID: "A", Workflow: communityTestWorkflow()}, {ID: "B", Workflow: communityTestWorkflow()}}}
				input, _ = json.Marshal(map[string]any{"kind": kind, "document": doc, "message": "Add a custom calculation"})
			}
			before := bytes.Clone(input)
			status, _, body, _ := authRequest(t, f, "POST", "/studio/assistant", input, studioBrowser(t, f))
			if status != 200 || calls.Load() != 2 || builds.Load() != 2 || !bytes.Contains(body, []byte("float64(42)")) || bytes.Contains(body, []byte("missingIdentifier")) || !bytes.Equal(input, before) {
				t.Fatalf("custom repair failed status=%d calls=%d builds=%d body=%.1000s", status, calls.Load(), builds.Load(), body)
			}
			oaCheckResponse(t, oaContract(t), "POST", "/studio/assistant", status, body)
		})
	}
}

func TestAssistantCompilerSharesSlotsAndClassifiesWorkerFailures(t *testing.T) {
	document, _ := json.Marshal(communityTestWorkflow())
	account := uuid.New()
	for _, test := range []struct {
		name   string
		status int
		body   string
		reason string
	}{
		{"busy", 429, "", "compiler_busy"},
		{"unavailable", 503, "private upstream error", "compiler_unavailable"},
		{"broken", 200, "not JSON", "compiler_unavailable"},
		{"wrong document", 200, `{"version":1,"workflow_sha256":"wrong"}`, "compiler_unavailable"},
		{"compile diagnostic", 422, `{"error":"compile workflow: # debuglet.workflow.build\n./main.go:17:2: undefined: calculation"}`, ""},
		{"toolchain unavailable", 422, `{"error":"workflow builds require go1.26.10 installed locally"}`, "compiler_unavailable"},
		{"compiler killed", 422, `{"error":"compile workflow: compile: signal: killed"}`, "compiler_unavailable"},
		{"success", 200, `{"version":1,"workflow_sha256":"` + studio.DocumentDigest(document) + `"}`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client := server.Client()
			client.Transport = assistantTestTransport{client.Transport, server.URL}
			h := &Handler{studio: &studioProxy{client: client, active: map[uuid.UUID]bool{}}}
			check := h.assistantCompileCheck(account)
			h.studio.acquire(account)
			_, err := check(t.Context(), "workflow", document)
			var failure *echo.HTTPError
			if !errors.As(err, &failure) || failure.Code != 429 || calls.Load() != 0 {
				t.Fatal("assistant bypassed existing account compiler slot")
			}
			h.studio.release(account)
			diagnostic, err := check(t.Context(), "workflow", document)
			if test.reason != "" {
				if !errors.As(err, &failure) || failure.Message.(ErrorResponse).Reason != test.reason || strings.Contains(failure.Error(), "private upstream") {
					t.Fatalf("unsafe error: %v", err)
				}
			} else if err != nil || (diagnostic != "") != (test.status == 422) {
				t.Fatalf("wrong worker outcome: %q %v", diagnostic, err)
			}
			if !h.studio.acquire(account) {
				t.Fatal("compiler slot leaked")
			}
			h.studio.release(account)
		})
	}
}

type assistantTestTransport struct {
	base    http.RoundTripper
	address string
}

func (t assistantTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	req.URL.Host = strings.TrimPrefix(t.address, "http://")
	return t.base.RoundTrip(req)
}

func TestAssistantCompilerCancellationReleasesSlot(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Transport = assistantTestTransport{client.Transport, server.URL}
	h := &Handler{studio: &studioProxy{client: client, active: map[uuid.UUID]bool{}}}
	account := uuid.New()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.assistantCompileCheck(account)(ctx, "workflow", json.RawMessage(`{}`))
	}()
	<-started
	cancel()
	<-done
	if !h.studio.acquire(account) {
		t.Fatal("cancelled check kept compiler capacity")
	}
}
