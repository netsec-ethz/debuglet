// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/studio"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func assistantStreamEvents(t *testing.T, body []byte) []assistantStreamEvent {
	t.Helper()
	contract := oaContract(t)
	var events []assistantStreamEvent
	for _, line := range strings.Split(string(body), "\n") {
		if line == "" || strings.HasPrefix(line, ":") {
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

func TestAssistantKeepaliveStopsAndJoinsWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	stop := startAssistantKeepalive(ctx, time.Millisecond, func() error {
		calls.Add(1)
		close(entered)
		<-release
		return ctx.Err()
	})
	select {
	case <-entered:
	case <-time.After(ccRequestBound):
		t.Fatal("keepalive did not write")
	}
	cancel()
	joined := make(chan struct{})
	go func() {
		stop()
		close(joined)
	}()
	select {
	case <-joined:
		t.Fatal("keepalive stop returned while a write was still active")
	default:
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(ccRequestBound):
		t.Fatal("keepalive did not finish after cancellation")
	}
	if calls.Load() != 1 {
		t.Fatal("keepalive wrote again after cancellation")
	}
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

func TestAssistantStreamForwardsProviderProgressBeforeCheckedResult(t *testing.T) {
	const summary = "I am arranging the HTTP check and its result."
	proposal := communityTestJSON(t, map[string]any{
		"message": "Ready to review.", "action": "", "edits": nil,
		"document": map[string]any{
			"version": 1, "name": "Shared measurement", "entry": "request",
			"nodes": []any{map[string]any{"id": "request", "block": "http", "inputs_json": `{"url":"https://example.test/"}`, "position": nil}},
			"edges": []any{}, "groups": []any{}, "custom_blocks": []any{},
		},
	})
	release := make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	defer finish()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if r.URL.Path != "/v1/responses" || request["stream"] != true || request["store"] != false {
			t.Error("progress request did not use a stateless Responses stream")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		emit := func(event map[string]any) {
			data, err := json.Marshal(event)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			w.(http.Flusher).Flush()
		}
		reasoning := map[string]any{"type": "reasoning", "id": "rs_private", "summary": []any{}, "encrypted_content": "encrypted-provider-state"}
		call := map[string]any{"type": "function_call", "id": "fc_proposal", "call_id": "call_proposal", "name": "propose_document", "status": "completed", "arguments": string(proposal)}
		emit(map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_fixture", "status": "in_progress"}})
		emit(map[string]any{"type": "response.output_item.added", "output_index": 0, "item": reasoning})
		emit(map[string]any{"type": "response.reasoning_text.delta", "item_id": "rs_private", "output_index": 0, "delta": "raw-provider-thought"})
		emit(map[string]any{"type": "response.reasoning_summary_text.delta", "item_id": "rs_private", "output_index": 0, "summary_index": 0, "delta": summary})
		emit(map[string]any{"type": "response.function_call_arguments.delta", "item_id": "fc_proposal", "output_index": 1, "delta": string(proposal)})
		select {
		case <-release:
			emit(map[string]any{"type": "response.completed", "response": map[string]any{"status": "completed", "output": []any{reasoning, call}}})
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(provider.Close)
	client, err := studio.NewAssistant(studio.AssistantConfig{Endpoint: provider.URL + "/v1/responses", Model: "test-model", APIKey: "provider-test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	f := ccNewFixtureWith(t, Assistant(client))
	ctx, cancel := context.WithTimeout(f.ctx, ccRequestBound)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "POST", f.root.URL+"/studio/assistant/stream", bytes.NewReader(assistantBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range studioBrowser(t, f) {
		request.Header.Set(name, value)
	}
	response, err := f.root.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("unexpected stream response: %d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	var body bytes.Buffer
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("provider progress was not flushed before completion: %v", err)
		}
		body.WriteString(line)
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var event assistantStreamEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			t.Fatal(err)
		}
		if event.Type == "result" || event.Type == "error" {
			t.Fatal("stream completed before the provider did")
		}
		if event.Type == "provider_progress" && event.Phase == "output" && event.OutputBytes > 0 {
			break
		}
	}
	finish()
	if _, err := io.Copy(&body, reader); err != nil {
		t.Fatal(err)
	}
	events := assistantStreamEvents(t, body.Bytes())
	var phases []string
	var summaries strings.Builder
	outputBytes := 0
	for _, event := range events {
		if event.Type == "provider_progress" {
			if len(phases) == 0 || phases[len(phases)-1] != event.Phase {
				phases = append(phases, event.Phase)
			}
			summaries.WriteString(event.SummaryDelta)
			if event.OutputBytes > outputBytes {
				outputBytes = event.OutputBytes
			}
		}
	}
	if strings.Join(phases, ",") != "accepted,reasoning,output" || summaries.String() != summary || outputBytes != len(proposal) {
		t.Fatalf("progress changed: phases=%v summary=%q bytes=%d", phases, summaries.String(), outputBytes)
	}
	last := events[len(events)-1]
	if events[0].Stage != "generating" || events[len(events)-2].Stage != "validating" || last.Type != "result" || last.Result == nil || len(last.Result.Document) == 0 {
		t.Fatalf("missing checked terminal result: %+v", events)
	}
	for _, private := range []string{"provider-test-secret", "encrypted-provider-state", "raw-provider-thought", "inputs_json", "function_call_arguments"} {
		if bytes.Contains(body.Bytes(), []byte(private)) {
			t.Fatalf("stream exposed private or partial provider data: %s", private)
		}
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
