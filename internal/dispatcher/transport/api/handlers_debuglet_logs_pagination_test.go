package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

const logsPaginationID = "a94c47e1-e09e-4ef2-a00f-e4db0eb4cdb0"

var (
	logsPaginationListQuery = regexp.QuoteMeta(
		"SELECT debuglet_logs.id, debuglet_logs.debuglet_id, debuglet_logs.timestamp, debuglet_logs.output FROM debuglet_logs INNER JOIN debuglets ON debuglet_logs.debuglet_id = debuglets.id WHERE uuid = ? AND debuglet_logs.id > ? ORDER BY debuglet_logs.id ASC LIMIT ?",
	)
	logsPaginationGetQuery = regexp.QuoteMeta(
		"SELECT id, uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, error, transaction_id, order_id, dispatcher_incarnation, session_id FROM debuglets WHERE uuid = ?",
	)
)

func newLogsPaginationServer(t *testing.T) (*echo.Echo, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sqlmock database: %v", err)
	}
	t.Cleanup(func() {
		mock.ExpectClose()
		if err := db.Close(); err != nil {
			t.Errorf("close sqlmock database: %v", err)
		}
	})

	e := echo.New()
	// This fixture drives one handler directly; the local development profile
	// keeps the pagination decisions the only thing under test.
	e.Use(AuthMiddleware(nil, true))
	e.GET("/debuglet/:id/logs", NewHandler(nil, db, zap.NewNop(), LocalDevelopment(true)).GetDebugletLogs)
	return e, mock
}

func serveLogsPaginationRequest(e *echo.Echo, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/debuglet/"+logsPaginationID+"/logs"+query, nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestGetDebugletLogsRejectsInvalidPaginationBeforeDatabaseQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		message string
	}{
		{name: "empty after", query: "?after=", message: "invalid after parameter: must be a non-negative integer"},
		{name: "malformed after", query: "?after=nope", message: "invalid after parameter: must be a non-negative integer"},
		{name: "overflowing after", query: "?after=9223372036854775808", message: "invalid after parameter: must be a non-negative integer"},
		{name: "negative after", query: "?after=-1", message: "invalid after parameter: must be a non-negative integer"},
		{name: "empty limit", query: "?limit=", message: "invalid limit parameter: must be a positive integer"},
		{name: "malformed limit", query: "?limit=nope", message: "invalid limit parameter: must be a positive integer"},
		{name: "overflowing limit", query: "?limit=9223372036854775808", message: "invalid limit parameter: must be a positive integer"},
		{name: "zero limit", query: "?limit=0", message: "invalid limit parameter: must be a positive integer"},
		{name: "negative limit", query: "?limit=-1", message: "invalid limit parameter: must be a positive integer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, mock := newLogsPaginationServer(t)
			rec := serveLogsPaginationRequest(e, tt.query)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			var body struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body.Message != tt.message {
				t.Fatalf("message = %q, want %q", body.Message, tt.message)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unexpected database access: %v", err)
			}
		})
	}
}

func TestGetDebugletLogsPaginationDefaultsAndBounds(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantAfter int64
		wantLimit int64
	}{
		{name: "omitted values use defaults", query: "", wantAfter: 0, wantLimit: 100},
		{name: "zero cursor is valid", query: "?after=0&limit=1", wantAfter: 0, wantLimit: 1},
		{name: "maximum limit", query: "?after=7&limit=1000", wantAfter: 7, wantLimit: 1000},
		{name: "oversized positive limit is clamped", query: "?after=7&limit=1001", wantAfter: 7, wantLimit: 1000},
	}

	id := uuid.MustParse(logsPaginationID)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, mock := newLogsPaginationServer(t)
			mock.ExpectQuery(logsPaginationListQuery).
				WithArgs(id, tt.wantAfter, tt.wantLimit).
				WillReturnRows(sqlmock.NewRows([]string{"id", "debuglet_id", "timestamp", "output"}))
			mock.ExpectQuery(logsPaginationGetQuery).
				WithArgs(id).
				WillReturnRows(debugletPaginationRow(id))

			rec := serveLogsPaginationRequest(e, tt.query)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			var response DebugletLogsResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.After != tt.wantAfter || response.State != "RunStateExited" || response.HasMore {
				t.Fatalf("unexpected response: %+v", response)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("database expectations: %v", err)
			}
		})
	}
}

func TestGetDebugletLogsPreservesValidPaginationAndOpaqueOutput(t *testing.T) {
	e, mock := newLogsPaginationServer(t)
	id := uuid.MustParse(logsPaginationID)
	wantOutput := []byte{0x00, 0xff, '\n'}
	mock.ExpectQuery(logsPaginationListQuery).
		WithArgs(id, int64(7), int64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "debuglet_id", "timestamp", "output"}).
			AddRow(int64(8), int64(1), time.Date(2026, 9, 10, 8, 30, 0, 0, time.UTC), wantOutput))
	mock.ExpectQuery(logsPaginationGetQuery).
		WithArgs(id).
		WillReturnRows(debugletPaginationRow(id))

	rec := serveLogsPaginationRequest(e, "?after=7&limit=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var response DebugletLogsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.After != 8 || response.HasMore || len(response.Logs) != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.Logs[0].Output != "AP8K" || response.Logs[0].Timestamp != "2026-09-10T08:30:00Z" {
		t.Fatalf("opaque log fields changed: %+v", response.Logs[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestClientLogsReportsHandlerValidationAsTypedHTTPError(t *testing.T) {
	e, mock := newLogsPaginationServer(t)
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		query := req.URL.Query()
		query.Set("after", "")
		req.URL.RawQuery = query.Encode()
		return http.DefaultTransport.RoundTrip(req)
	})
	c, err := client.New(srv.URL, client.Options{HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = c.Logs(context.Background(), logsPaginationID, client.LogOptions{Limit: 1})
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error = %T %v, want *client.HTTPError", err, err)
	}
	if httpErr.StatusCode != http.StatusBadRequest || httpErr.Message != "invalid after parameter: must be a non-negative integer" {
		t.Fatalf("unexpected HTTP error: %+v", httpErr)
	}
	if httpErr.Method != http.MethodGet || httpErr.Path != "/debuglet/"+logsPaginationID+"/logs" {
		t.Fatalf("unexpected request identity: %+v", httpErr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected database access: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func debugletPaginationRow(id uuid.UUID) *sqlmock.Rows {
	now := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	return sqlmock.NewRows([]string{
		"id", "uuid", "start_time", "end_time", "usage", "ceil_bw", "executor_id", "addresses", "state", "error",
		"transaction_id", "order_id", "dispatcher_incarnation", "session_id",
	}).AddRow(int64(1), id.String(), now, now, int64(0), int64(0), "executor", "", int64(5), sql.NullString{}, "tx", int64(1), "incarnation", "session")
}
