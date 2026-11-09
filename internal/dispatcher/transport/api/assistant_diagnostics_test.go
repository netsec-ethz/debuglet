// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/studio"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestAssistantFailureLogsSafeProviderStatusOnBothRoutes(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "private-provider-body provider-test-secret", http.StatusBadRequest)
	}))
	defer provider.Close()
	assistant, err := studio.NewAssistant(studio.AssistantConfig{Endpoint: provider.URL, Model: "test-model", APIKey: "provider-test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	f := ccNewFixtureLogged(t, logger, Assistant(assistant))
	f.root.Config.Handler.(*echo.Echo).Use(RequestLog(logger))
	browser := studioBrowser(t, f)
	for _, route := range []string{"/studio/assistant", "/studio/assistant/stream"} {
		status, _, body, response := authRequest(t, f, http.MethodPost, route, assistantBody(t), browser)
		want := http.StatusBadGateway
		if strings.HasSuffix(route, "/stream") {
			want = http.StatusOK
			events := assistantStreamEvents(t, body)
			if len(events) != 2 || events[1].Status != http.StatusBadGateway || events[1].Error == nil || events[1].Error.Reason != "provider_unavailable" {
				t.Fatalf("unexpected failure events: %+v", events)
			}
		}
		if status != want || strings.Contains(string(body), "private-provider-body") || strings.Contains(string(body), "provider-test-secret") {
			t.Fatalf("unsafe failure response: status %d", status)
		}
		entries := logs.FilterMessage("Assistant request failed").All()
		if len(entries) == 0 {
			t.Fatal("provider failure was not logged")
		}
		fields := entries[len(entries)-1].ContextMap()
		id := response.Header.Get(echo.HeaderXRequestID)
		if _, err := uuid.Parse(id); err != nil {
			t.Fatalf("missing generated request identity: %q", id)
		}
		if len(fields) != 4 || fields["request_id"] != id || fields["reason"] != "provider_unavailable" || fields["provider_status"] != int64(http.StatusBadRequest) {
			t.Fatalf("unsafe or incomplete diagnostic: %+v", fields)
		}
		if latency, ok := fields["latency"].(time.Duration); !ok || latency <= 0 {
			t.Fatalf("missing elapsed time: %#v", fields["latency"])
		}
	}
	if entries := logs.FilterMessage("Assistant request failed").All(); len(entries) != 2 {
		t.Fatalf("wanted one diagnostic per request, got %d", len(entries))
	}
}

func TestAssistantDiagnosticRejectsUnboundedErrorFields(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	h := &Handler{logger: zap.New(core)}
	c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/studio/assistant/stream", nil), httptest.NewRecorder())
	for _, err := range []error{
		&studio.AssistantError{Code: "private-code", Message: "private-message", ProviderStatus: 123456},
		echo.NewHTTPError(http.StatusServiceUnavailable, ErrorResponse{Reason: "private-code", Message: "private-message"}),
	} {
		h.logAssistantFailure(c, err, context.Canceled, time.Millisecond)
	}
	for _, entry := range logs.All() {
		fields := entry.ContextMap()
		if len(fields) != 4 || fields["provider_status"] != int64(0) || (fields["reason"] != "canceled" && fields["reason"] != "unknown") {
			t.Fatalf("unbounded diagnostic: %+v", fields)
		}
	}
}
