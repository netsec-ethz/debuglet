// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func recoveryFixture() RecoveryDocument {
	return RecoveryDocument{ID: fixtureID, ExecutorID: fixtureExecutor, State: StateExited, Error: "workload failed", CheckedAt: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC), ControlStatus: "legacy", Observation: RecoveryObservation{Classification: "unavailable"}}
}

func TestRecoveryPreservesNullableProvenanceAndFutureClassifications(t *testing.T) {
	f := newFakeServer(t, "/api")
	for _, classification := range []string{"unavailable", "failed", "future_unknown"} {
		doc := recoveryFixture()
		doc.Observation.Classification = classification
		data, _ := json.Marshal(doc)
		f.handle("GET /debuglet/{id}/recovery", jsonHandler(http.StatusOK, string(data)))
		f.reset()
		got, err := f.client(t, Options{}).Recovery(t.Context(), fixtureID)
		if err != nil || got.Observation.Classification != classification || got.Error != doc.Error {
			t.Fatalf("inspection: %+v, %v", got, err)
		}
		encoded, _ := json.Marshal(got)
		if string(encoded) != string(data) || !strings.Contains(string(encoded), `"observer":null`) || !strings.Contains(string(encoded), `"current_at_check":null`) {
			t.Fatalf("JSON changed nullable provenance: %s", encoded)
		}
		requests := f.requests()
		if len(requests) != 1 || requests[0].Path != "/api/debuglet/"+fixtureID+"/recovery" || requests[0].Method != http.MethodGet {
			t.Fatalf("requests: %+v", requests)
		}
	}
}

func TestRecoveryRejectsInconsistentRecognizedFields(t *testing.T) {
	f := newFakeServer(t, "")
	for name, change := range map[string]func(map[string]any){
		"missing required provenance":  func(d map[string]any) { delete(d["observation"].(map[string]any), "observer") },
		"null error":                   func(d map[string]any) { d["error"] = nil },
		"missing error":                func(d map[string]any) { delete(d, "error") },
		"wrong ID":                     func(d map[string]any) { d["id"] = "other" },
		"missing date":                 func(d map[string]any) { delete(d, "checked_at") },
		"unproven unavailable binding": func(d map[string]any) { d["control_status"] = "unavailable" },
		"unproven current binding":     func(d map[string]any) { d["control_status"] = "current" },
		"absence without observation":  func(d map[string]any) { d["observation"].(map[string]any)["classification"] = "absent" },
		"retained without metadata":    func(d map[string]any) { d["observation"].(map[string]any)["classification"] = "retained_unstarted" },
		"false receive date":           func(d map[string]any) { d["observation"].(map[string]any)["received_at"] = "2026-09-28T12:00:00Z" },
	} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(recoveryFixture())
			var fields map[string]any
			_ = json.Unmarshal(data, &fields)
			change(fields)
			data, _ = json.Marshal(fields)
			f.handle("GET /debuglet/{id}/recovery", jsonHandler(http.StatusOK, string(data)))
			if _, err := f.client(t, Options{}).Recovery(t.Context(), fixtureID); err == nil {
				t.Fatal("accepted inconsistent recovery document")
			} else {
				asProtocolError(t, err)
			}
		})
	}
}

func TestRecoveryKeepsHTTPAndContextErrors(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("GET /debuglet/{id}/recovery", jsonHandler(http.StatusNotFound, `{"code":"not_found","message":"debuglet not found"}`))
	c := f.client(t, Options{})
	_, err := c.Recovery(t.Context(), fixtureID)
	if httpError := asHTTPError(t, err); httpError.Code != "not_found" || httpError.StatusCode != 404 {
		t.Fatalf("lost typed HTTP error: %+v", httpError)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Recovery(ctx, fixtureID); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	f.handle("GET /debuglet/{id}/recovery", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	c = f.client(t, Options{RequestTimeout: 20 * time.Millisecond})
	if _, err := c.Recovery(t.Context(), fixtureID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost request bound: %v", err)
	}
}

func TestRecoveryAcceptsDatedHistoricalRetention(t *testing.T) {
	f := newFakeServer(t, "")
	for _, started := range []bool{false, true} {
		doc := recoveryFixture()
		doc.ControlStatus = "unavailable"
		doc.OriginalBinding = &ControlBinding{DispatcherIncarnation: fixtureID, SessionID: "2fe98d48-ab11-4ccb-b9e9-84c94c581c6e"}
		current := false
		doc.Observation = RecoveryObservation{Classification: "retained_unstarted", Observer: &RecoveryObserver{ExecutorID: fixtureExecutor, Binding: ControlBinding{DispatcherIncarnation: fixtureID, SessionID: "92ab28aa-189a-4fd0-9924-abcdef123456"}}, ReceivedAt: &doc.CheckedAt, CurrentAtCheck: &current, Retained: &RetainedRun{OriginalBinding: doc.OriginalBinding, Started: started}}
		if started {
			doc.Observation.Classification = "started_unknown"
			doc.Observation.Retained.StartedAt = &doc.CheckedAt
		}
		data, _ := json.Marshal(doc)
		f.handle("GET /debuglet/{id}/recovery", jsonHandler(http.StatusOK, string(data)))
		got, err := f.client(t, Options{}).Recovery(t.Context(), fixtureID)
		if err != nil || got.Observation.CurrentAtCheck == nil || *got.Observation.CurrentAtCheck || got.Observation.Retained.Started != started {
			t.Fatalf("lost historical observation: %+v, %v", got, err)
		}
		doc.ControlStatus = "current"
		data, _ = json.Marshal(doc)
		f.handle("GET /debuglet/{id}/recovery", jsonHandler(http.StatusOK, string(data)))
		if _, err := f.client(t, Options{}).Recovery(t.Context(), fixtureID); err != nil {
			t.Fatalf("historical observer conflicts with current original control: %v", err)
		}
		current = true
		data, _ = json.Marshal(doc)
		f.handle("GET /debuglet/{id}/recovery", jsonHandler(http.StatusOK, string(data)))
		if _, err := f.client(t, Options{}).Recovery(t.Context(), fixtureID); err == nil {
			t.Fatal("accepted two different current control bindings")
		} else {
			asProtocolError(t, err)
		}
	}
}
