// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"go.uber.org/zap"
)

func TestRecoveryOnlyInspectsTheCallersKnownRun(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, ownToken, own := authAccount(t, f, "recovery owner")
	_, otherToken, _ := authAccount(t, f, "other account")
	batch, err := client.Prepare([]client.Request{ccRequest([]string{"127.0.0.1:8080"})})
	if err != nil {
		t.Fatal(err)
	}
	submitted, err := own.SubmitTEST(f.ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	id := submitted.IDs[0]
	before, err := own.Status(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(f.d, f.db, zap.NewNop())
	e := echo.New()
	h.RegisterRoutes(e)
	for _, tc := range []struct {
		name, id, token string
		status          int
	}{
		{"owner", id, ownToken, http.StatusOK},
		{"other account", id, otherToken, http.StatusNotFound},
		{"anonymous", id, "", http.StatusUnauthorized},
		{"unknown", uuid.NewString(), ownToken, http.StatusNotFound},
		{"malformed", "not-a-uuid", ownToken, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/debuglet/"+tc.id+"/recovery", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if rec.Code == http.StatusOK {
				var doc client.RecoveryDocument
				if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				if doc.ID != id || doc.ControlStatus != "current" || doc.Observation.Classification != "not_attempted" || doc.Observation.Observer != nil {
					t.Fatalf("unexpected current run: %+v", doc)
				}
			}
		})
	}
	after, err := own.Status(f.ctx, id)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("inspection changed status: before=%+v after=%+v error=%v", before, after, err)
	}
}

func TestRecoveryDatesMatchTheDocumentedFormat(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"2026-09-28T12:00:00Z", true},
		{"2026-09-28T12:00:00.123456789Z", true},
		{"2026-09-28", false},
		{"2026-13-28T12:00:00Z", false},
		{"not a date", false},
	} {
		problems := validateString(map[string]any{"format": "date-time"}, tc.value, "checked_at")
		if (len(problems) == 0) != tc.valid {
			t.Errorf("%q: %v", tc.value, problems)
		}
	}
}
