// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func providerEvent(kind, delta string) string {
	data, _ := json.Marshal(map[string]any{"type": kind, "delta": delta})
	return "data: " + string(data) + "\n\n"
}

const completedProviderEvent = "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n"

func TestAssistantProviderStreamReportsOnlyRealSummariesAndByteCounts(t *testing.T) {
	stream := ": keepalive\r\n\r\n" +
		providerEvent("response.created", "") + providerEvent("response.in_progress", "") +
		providerEvent("response.reasoning_text.delta", "private reasoning") +
		providerEvent("response.reasoning_summary_text.delta", "Checking the inputs.") +
		providerEvent("response.function_call_arguments.delta", "é") +
		providerEvent("response.function_call_arguments.delta", "{}​") + completedProviderEvent
	var progress []AssistantProgress
	data, err := assistantReadResponseStream(t.Context(), strings.NewReader(stream), func(event AssistantProgress) error {
		progress = append(progress, event)
		return nil
	})
	want := []AssistantProgress{{Phase: "accepted"}, {Phase: "reasoning", SummaryDelta: "Checking the inputs."}, {Phase: "output", OutputBytes: 2}, {Phase: "output", OutputBytes: 7}}
	if err != nil || !reflect.DeepEqual(progress, want) || !strings.Contains(string(data), `"status":"completed"`) {
		t.Fatalf("unexpected progress/result: %+v %v", progress, err)
	}
}

func TestAssistantProviderSummaryIsBoundedUTF8(t *testing.T) {
	stream := providerEvent("response.reasoning_summary_text.delta", strings.Repeat("é", 4095)+"a€") +
		providerEvent("response.reasoning_summary_text.delta", "remaining") + completedProviderEvent
	var summary string
	_, err := assistantReadResponseStream(t.Context(), strings.NewReader(stream), func(event AssistantProgress) error {
		summary += event.SummaryDelta
		return nil
	})
	if err != nil || len(summary) != assistantTextLimit || !utf8.ValidString(summary) {
		t.Fatalf("unbounded/invalid summary: bytes=%d err=%v", len(summary), err)
	}
}

func TestAssistantProviderStreamRejectsPartialOrUnboundedReplies(t *testing.T) {
	for name, stream := range map[string]string{
		"eof":          providerEvent("response.created", ""),
		"unterminated": strings.TrimSuffix(completedProviderEvent, "\n\n"),
		"bad_json":     "data: {broken}\n\n",
		"oversize":     "data: " + strings.Repeat("x", assistantEventLimit+1) + "\n\n",
		"total_limit":  strings.Repeat(": padding\n", assistantStreamLimit/10+1) + completedProviderEvent,
		"event_count":  strings.Repeat(providerEvent("ignored", ""), assistantEventCount+1) + completedProviderEvent,
		"arguments":    providerEvent("response.function_call_arguments.delta", strings.Repeat("x", assistantResponseLimit)) + providerEvent("response.function_call_arguments.delta", "x") + completedProviderEvent,
		"mismatch":     "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"completed\"}}\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := assistantReadResponseStream(t.Context(), strings.NewReader(stream), nil)
			if !errors.Is(err, ErrAssistantInvalidReply) || len(data) != 0 {
				t.Fatalf("accepted invalid stream: %v", err)
			}
		})
	}
}

func TestAssistantProviderStreamObserverFailureStopsTransport(t *testing.T) {
	stopped := errors.New("reader disconnected")
	release := make(chan struct{})
	defer close(release)
	client := responsesFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, providerEvent("response.created", ""))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	_, err := client.ReplyProgress(t.Context(), assistantInput(t, "workflow", sampleWorkflow()), nil, func(progress AssistantProgress) error {
		if progress.Phase == "accepted" {
			return stopped
		}
		return nil
	})
	if !errors.Is(err, stopped) {
		t.Fatalf("observer failure lost: %v", err)
	}
}

func TestAssistantProviderStreamCancellationAndDeadline(t *testing.T) {
	client := responsesFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, providerEvent("response.created", ""))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	if client.client.Timeout != 3*time.Minute || client.client.Transport.(*http.Transport).ResponseHeaderTimeout != 3*time.Minute {
		t.Fatal("provider and application deadlines differ")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, err := client.ReplyProgress(ctx, assistantInput(t, "workflow", sampleWorkflow()), nil, func(progress AssistantProgress) error {
		if progress.Phase == "accepted" {
			cancel()
		}
		return nil
	})
	var failure *AssistantError
	if !errors.As(err, &failure) || failure.Code != "canceled" {
		t.Fatalf("stream cancellation lost: %v", err)
	}
}
