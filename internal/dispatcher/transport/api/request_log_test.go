// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestRequestLogUsesGeneratedIdentityAndSafeRoute(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	e := echo.New()
	e.Use(RequestLog(logger))
	h := &Handler{logger: logger}
	e.HTTPErrorHandler = h.errorHandler
	var handlerID string
	e.POST("/test/:id", func(c echo.Context) error {
		handlerID = daemonlog.RequestID(c.Request().Context())
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	})
	req := httptest.NewRequest(http.MethodPost, "/test/secret-path?code=secret-query", strings.NewReader("secret-body"))
	req.Header.Set(echo.HeaderXRequestID, "caller-id")
	req.Header.Set(echo.HeaderAuthorization, "Bearer secret-token")
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("changed error response: %d %s", response.Code, response.Body)
	}
	id := response.Header().Get(echo.HeaderXRequestID)
	if _, err := uuid.Parse(id); err != nil || id != handlerID {
		t.Fatalf("identity not propagated: %q %q", id, handlerID)
	}
	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("request logged %d times", len(entries))
	}
	fields := entries[0].ContextMap()
	if len(fields) != 5 || fields["request_id"] != id || fields["route"] != "/test/:id" || fields["method"] != "POST" || fields["status"] != int64(400) {
		t.Fatalf("unexpected HTTP log: %+v", fields)
	}
	// Unmatched paths also never enter the log; a fresh server ID belongs to
	// each request, including errors that did not reach a handler.
	missing := httptest.NewRecorder()
	e.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/unknown-secret?token=another-secret", nil))
	last := logs.All()[1].ContextMap()
	if last["route"] != "unknown" || last["request_id"] == id || missing.Code != http.StatusNotFound {
		t.Fatalf("unmatched request: %+v", last)
	}
}
