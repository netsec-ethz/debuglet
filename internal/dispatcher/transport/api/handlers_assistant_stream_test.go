// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func assistantStreamEvents(t *testing.T, body []byte) []assistantStreamEvent {
	t.Helper()
	contract := oaContract(t)
	var events []assistantStreamEvent
	for _, line := range strings.Split(string(body), "\n") {
		if line == "" {
			continue
		}
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			t.Fatalf("unexpected stream record: %.100s", line)
		}
		for _, problem := range contract.validateJSON(contract.schemas["StudioAssistantStreamEvent"], []byte(data), "assistant stream event") {
			t.Error(problem)
		}
		var event assistantStreamEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

func TestAssistantStreamChecksBeforeHeadersAndDoesNotLeakFailures(t *testing.T) {
	var calls atomic.Int32
	f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "provider-test-secret upstream internals", 500)
	}))
	browser := studioBrowser(t, f)
	for _, test := range []struct {
		target  string
		body    []byte
		headers map[string]string
		want    int
	}{
		{"/studio/assistant/stream", assistantBody(t), nil, 401},
		{"/studio/assistant/stream", assistantBody(t), map[string]string{"Cookie": browser["Cookie"]}, 403},
		{"/studio/assistant/stream", []byte(`{}`), browser, 400},
		{"/studio/assistant/stream?extra=1", assistantBody(t), browser, 400},
	} {
		status, _, body, response := authRequest(t, f, "POST", test.target, test.body, test.headers)
		if status != test.want || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("pre-stream rejection %d: %s", status, body)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected request reached provider")
	}
	status, _, body, response := authRequest(t, f, "POST", "/studio/assistant/stream", assistantBody(t), browser)
	if status != 200 || response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("stream response %d: %s", status, body)
	}
	if bytes.Contains(body, []byte("provider-test-secret")) || bytes.Contains(body, []byte("upstream internals")) {
		t.Fatal("private provider failure leaked")
	}
	events := assistantStreamEvents(t, body)
	if len(events) != 2 || events[0].Stage != "generating" || events[1].Type != "error" || events[1].Status != 502 || events[1].Error == nil || events[1].Error.Reason != "provider_unavailable" {
		t.Fatalf("failure events: %+v", events)
	}
	// A terminal stream releases the same account slot used by ordinary JSON.
	if status, _ := authStatus(t, f, "POST", "/studio/assistant", assistantBody(t), browser); status != 502 || calls.Load() != 2 {
		t.Fatalf("capacity was not released: %d", status)
	}
}

func TestAssistantStreamEmitsValidatedResult(t *testing.T) {
	f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proposal, _ := json.Marshal(map[string]any{"message": "Ready to review.", "document": communityTestWorkflow()})
		studioJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "proposal", "type": "function", "function": map[string]any{"name": "propose_document", "arguments": string(proposal)}}}}}}})
	}))
	status, _, body, _ := authRequest(t, f, "POST", "/studio/assistant/stream", assistantBody(t), studioBrowser(t, f))
	if status != 200 {
		t.Fatalf("stream status %d: %s", status, body)
	}
	events := assistantStreamEvents(t, body)
	if len(events) != 3 || events[0].Stage != "generating" || events[1].Stage != "validating" || events[2].Type != "result" || events[2].Result == nil || len(events[2].Result.Document) == 0 {
		t.Fatalf("result events: %+v", events)
	}
}

func TestAssistantStreamReportsCompilerUnavailableWithoutProposal(t *testing.T) {
	f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wf := workflow.Workflow{Version: 1, Name: "Calculation", Entry: "calculate", Nodes: []workflow.Node{{ID: "calculate", Block: "calculate"}}, Edges: []workflow.Edge{},
			CustomBlocks: []workflow.CustomBlock{{ID: "calculate", Label: "Calculate", Code: "return nil, nil"}}}
		proposal, _ := json.Marshal(map[string]any{"message": "Ready to review.", "document": wf})
		studioJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "proposal", "type": "function", "function": map[string]any{"name": "propose_document", "arguments": string(proposal)}}}}}}})
	}))
	status, _, body, _ := authRequest(t, f, "POST", "/studio/assistant/stream", assistantBody(t), studioBrowser(t, f))
	if status != 200 {
		t.Fatalf("stream status %d: %s", status, body)
	}
	events := assistantStreamEvents(t, body)
	if len(events) != 4 || events[2].Stage != "compiling" || events[3].Type != "error" || events[3].Status != 503 || events[3].Error == nil || events[3].Error.Reason != "compiler_unavailable" || events[3].Result != nil {
		t.Fatalf("compiler failure events: %+v", events)
	}
}

func TestAssistantStreamFlushesBeforeProviderCompletesAndCancelsWork(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	browser := studioBrowser(t, f)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "POST", f.root.URL+"/studio/assistant/stream", bytes.NewReader(assistantBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range browser {
		request.Header.Set(name, value)
	}
	response, err := f.root.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	if err != nil || !strings.Contains(line, `"stage":"generating"`) {
		t.Fatalf("no immediate generation event: %q, %v", line, err)
	}
	select {
	case <-started:
	case <-time.After(ccRequestBound):
		t.Fatal("provider was not called")
	}
	if status, _ := authStatus(t, f, "POST", "/studio/assistant", assistantBody(t), browser); status != 429 {
		t.Fatalf("stream did not hold shared account capacity: %d", status)
	}
	cancel()
	response.Body.Close()
	select {
	case <-stopped:
	case <-time.After(ccRequestBound):
		t.Fatal("disconnect did not cancel provider work")
	}
}
