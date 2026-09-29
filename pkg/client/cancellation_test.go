// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestCancellationInspectionDoesNotRetryUnknownDelivery(t *testing.T) {
	f := newFakeServer(t, "/api")
	doc := CancellationDocument{ID: fixtureID, RequestID: "b85c3ccb-c486-40e1-ae49-93e1d2c8ac52", ExecutorID: fixtureExecutor, RequestedAt: time.Now().UTC(), CheckedAt: time.Now().UTC(), Disposition: "unresolved", Reason: "original_binding_unavailable", State: StateExited}
	data, _ := json.Marshal(doc)
	f.handle("GET /debuglet/{id}/cancellation", jsonHandler(http.StatusOK, string(data)))
	got, err := f.client(t, Options{}).Cancellation(t.Context(), fixtureID)
	if err != nil || got.AcknowledgedAt != nil || got.Disposition != "unresolved" {
		t.Fatalf("inspection: %+v, %v", got, err)
	}
	if requests := f.requests(); len(requests) != 1 || requests[0].Method != http.MethodGet {
		t.Fatalf("unexpected requests: %+v", requests)
	}
	doc.Disposition = "acknowledged"
	data, _ = json.Marshal(doc)
	f.handle("GET /debuglet/{id}/cancellation", jsonHandler(http.StatusOK, string(data)))
	if _, err := f.client(t, Options{}).Cancellation(t.Context(), fixtureID); err == nil {
		t.Fatal("accepted acknowledgement with no evidence")
	} else {
		asProtocolError(t, err)
	}
	// Future disposition strings remain inspectable with their evidence.
	doc.Disposition = "future_status"
	now := time.Now().UTC()
	doc.AttemptedAt, doc.AcknowledgedAt = &now, &now
	doc.OriginalBinding = &ControlBinding{DispatcherIncarnation: "1a3cfe2c-38ca-409f-9e58-a3fc0c7ee5a3", SessionID: "617edb2e-0bfe-42e6-b23d-d60d16d9c1d1"}
	data, _ = json.Marshal(doc)
	f.handle("GET /debuglet/{id}/cancellation", jsonHandler(http.StatusOK, string(data)))
	if got, err := f.client(t, Options{}).Cancellation(t.Context(), fixtureID); err != nil || got.Disposition != "future_status" {
		t.Fatalf("future inspection: %+v, %v", got, err)
	}

}

func TestCancellationInspectionRejectsContradictoryEvidence(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	earlier := now.Add(-time.Hour) // Clock steps do not invalidate historical evidence.
	binding := &ControlBinding{DispatcherIncarnation: "1a3cfe2c-38ca-409f-9e58-a3fc0c7ee5a3", SessionID: "617edb2e-0bfe-42e6-b23d-d60d16d9c1d1"}
	for _, tc := range []struct {
		name, disposition, reason string
		binding                   *ControlBinding
		attempted, acknowledged   *time.Time
		valid                     bool
	}{
		{"requested", "requested", "", binding, nil, nil, true},
		{"requested with attempt", "requested", "", binding, &now, nil, false},
		{"requested with acknowledgement", "requested", "", binding, &now, &now, false},
		{"requested with failure", "requested", "executor_refused", binding, nil, nil, false},
		{"attempted", "delivery_attempted", "", binding, &now, nil, true},
		{"attempted without date", "delivery_attempted", "", binding, nil, nil, false},
		{"attempted without binding", "delivery_attempted", "", nil, &now, nil, false},
		{"attempted with failure", "delivery_attempted", "executor_refused", binding, &now, nil, false},
		{"acknowledged without binding", "acknowledged", "", nil, &now, &now, false},
		{"acknowledged despite clock step", "acknowledged", "", binding, &now, &earlier, true},
		{"unresolved legacy", "unresolved", "original_binding_unavailable", nil, nil, nil, true},
		{"unresolved attempted", "unresolved", "transport_outcome_unknown", binding, &now, nil, true},
		{"unresolved without reason", "unresolved", "", binding, &now, nil, false},
		{"unresolved with acknowledgement", "unresolved", "executor_refused", binding, &now, &now, false},
		{"not needed", "not_needed", "already_terminal", binding, nil, nil, true},
		{"not needed legacy", "not_needed", "already_terminal", nil, nil, nil, true},
		{"not needed without reason", "not_needed", "", binding, nil, nil, false},
		{"not needed with attempt", "not_needed", "already_terminal", binding, &now, nil, false},
		{"not needed with acknowledgement", "not_needed", "already_terminal", binding, &now, &now, false},
		{"future with evidence", "future_status", "future_reason", binding, &now, &earlier, true},
		{"future with missing binding", "future_status", "future_reason", nil, &now, &now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, "")
			doc := CancellationDocument{ID: fixtureID, RequestID: "b85c3ccb-c486-40e1-ae49-93e1d2c8ac52", ExecutorID: fixtureExecutor, RequestedAt: now, CheckedAt: earlier, OriginalBinding: tc.binding, AttemptedAt: tc.attempted, AcknowledgedAt: tc.acknowledged, Disposition: tc.disposition, Reason: tc.reason, State: StateExited}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			f.handle("GET /debuglet/{id}/cancellation", jsonHandler(http.StatusOK, string(data)))
			got, err := f.client(t, Options{}).Cancellation(t.Context(), fixtureID)
			if tc.valid {
				if err != nil || got.Disposition != tc.disposition || got.Reason != tc.reason {
					t.Fatalf("inspection: %+v, %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("accepted contradictory evidence: %+v", got)
			} else {
				asProtocolError(t, err)
			}
			if requests := f.requests(); len(requests) != 1 || requests[0].Method != http.MethodGet {
				t.Fatalf("inspection retried or delivered: %+v", requests)
			}
		})
	}
}
