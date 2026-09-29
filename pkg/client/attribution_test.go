// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

const fixtureCandidates = `{"ip":"192.0.2.7","at":"2026-09-29T10:00:00.5Z","retained_from":"2026-07-01T00:00:00Z","truncated":false,
"candidates":[{"executor_id":"exec-zrh-1","run_id":"6f1c2b9e-8a44-4c55-9d1e-2b7f1f7c1a01","active_from":"2026-09-29T09:59:00Z","active_to":"2026-09-29T10:05:00Z","ip_source":"observed",
"schedule":{"chain_id":"00ff","k0":"AQID","t0_unix_ns":1790000000000000000,"epoch_seconds":60,"disclosure_delay_epochs":15,"chain_length":10080,"tag_spec":1},
"disclosed_through":42,"disclosed_through_at_ns":1790003420000000000,"next_disclosure_at_ns":1790003480000000000}]}`

func TestAttributionCandidatesNeedNoCredential(t *testing.T) {
	f := newFakeServer(t, "/api")
	f.handle("GET /attribution/candidates", jsonHandler(http.StatusOK, fixtureCandidates))
	at := time.Date(2026, 9, 29, 10, 0, 0, 500_000_000, time.UTC)
	doc, err := f.client(t, Options{}).AttributionCandidates(t.Context(), "192.0.2.7", at)
	if err != nil || len(doc.Candidates) != 1 || doc.Candidates[0].Schedule.EpochSeconds != 60 || doc.Candidates[0].DisclosedThrough != 42 ||
		doc.Candidates[0].DisclosedThroughAtNs != 1790003420000000000 || doc.Candidates[0].NextDisclosureAtNs != 1790003480000000000 {
		t.Fatalf("candidates: %+v, %v", doc, err)
	}
	requests := f.requests()
	if len(requests) != 1 || requests[0].Header.Get("Authorization") != "" {
		t.Fatalf("requests: %+v", requests)
	}
	query, _ := url.ParseQuery(requests[0].Query)
	if query.Get("ip") != "192.0.2.7" || query.Get("at") != "2026-09-29T10:00:00.5Z" {
		t.Fatalf("query %q", requests[0].Query)
	}
	if _, err := f.client(t, Options{}).AttributionCandidates(t.Context(), "not-an-ip", at); err == nil {
		t.Fatal("accepted an address that is not an IP")
	}
	// A candidate without a run identifier is refused.
	f.handle("GET /attribution/candidates", jsonHandler(http.StatusOK, `{"ip":"192.0.2.7","at":"2026-09-29T10:00:00Z","retained_from":"2026-07-01T00:00:00Z","truncated":false,
"candidates":[{"executor_id":"e","run_id":"","active_from":"2026-09-29T09:59:00Z","active_to":"2026-09-29T10:05:00Z","ip_source":"observed","schedule":{"chain_id":"00ff","k0":"AQID","t0_unix_ns":0,"epoch_seconds":60,"disclosure_delay_epochs":15,"chain_length":0,"tag_spec":1},"disclosed_through":0,"disclosed_through_at_ns":0,"next_disclosure_at_ns":0}]}`))
	if _, err := f.client(t, Options{}).AttributionCandidates(t.Context(), "192.0.2.7", at); err == nil {
		t.Fatal("accepted a candidate without a run")
	} else {
		asProtocolError(t, err)
	}
}

func TestAttributionKeysValidatesThePage(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("GET /attribution/keys", jsonHandler(http.StatusOK, `{"executor_id":"e","chain_id":"c","keys":[{"epoch":3,"key":"AQ=="},{"epoch":5,"key":"Ag=="}],"next_epoch":1027}`))
	page, err := f.client(t, Options{}).AttributionKeys(t.Context(), "e", "c", 3, 0)
	if err != nil || len(page.Keys) != 2 || page.NextEpoch == nil || *page.NextEpoch != 1027 {
		t.Fatalf("page: %+v, %v", page, err)
	}
	query, _ := url.ParseQuery(f.requests()[0].Query)
	if query.Get("from_epoch") != "3" || query.Has("to_epoch") || query.Get("executor_id") != "e" || query.Get("chain_id") != "c" {
		t.Fatalf("query %q", f.requests()[0].Query)
	}
	for name, body := range map[string]string{
		"descending epochs": `{"executor_id":"e","chain_id":"c","keys":[{"epoch":5,"key":"AQ=="},{"epoch":4,"key":"Ag=="}],"next_epoch":null}`,
		"another chain":     `{"executor_id":"e","chain_id":"d","keys":[],"next_epoch":null}`,
		"beyond the page":   `{"executor_id":"e","chain_id":"c","keys":[{"epoch":2000,"key":"AQ=="}],"next_epoch":null}`,
		"wrong next page":   `{"executor_id":"e","chain_id":"c","keys":[],"next_epoch":7}`,
	} {
		f.handle("GET /attribution/keys", jsonHandler(http.StatusOK, body))
		if _, err := f.client(t, Options{}).AttributionKeys(t.Context(), "e", "c", 3, 0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := f.client(t, Options{}).AttributionKeys(t.Context(), "e", "c", 9, 3); err == nil {
		t.Fatal("accepted a descending range")
	}
}
