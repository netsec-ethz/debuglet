// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const fixtureQuote = `{"pricing_rule":"bw-s-ceil-ms-v1","currency":"TEST","unit":"TEST units","total":"40",` +
	`"orders":[{"order_id":0,"executor_id":"fixture-executor","price":"40","errors":[]}],"errors":[]}`

// Quote sends the TEST intent body of the frozen batch to the quote route,
// requires the first contract version that has it and returns the decoded
// quote.
func TestQuoteSendsTheIntentBody(t *testing.T) {
	f := newFakeServer(t, "/api")
	f.handle("POST /payment/quote", jsonHandler(http.StatusOK, fixtureQuote))
	quote, err := f.client(t, Options{}).Quote(testContext(t), sampleBatch(t))
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if quote.Total != "40" || quote.PricingRule != "bw-s-ceil-ms-v1" || len(quote.Orders) != 1 || quote.Orders[0].Price != "40" {
		t.Fatalf("quote %+v", quote)
	}
	requests := f.requests()
	if len(requests) != 1 {
		t.Fatalf("%d requests, want one", len(requests))
	}
	want := `{"debuglets":` + sampleDebuglets + `,"payment_method":"TEST","refund_address":""}`
	if requests[0].Path != "/api/payment/quote" || string(requests[0].Body) != want {
		t.Fatalf("quote request %s %s", requests[0].Path, requests[0].Body)
	}
	if got := requests[0].Header.Get("Debuglet-API-Version"); got != "1.15" {
		t.Fatalf("quote announced %q, want 1.15", got)
	}
}

// A quote that does not answer for every order of the batch is a protocol
// failure, as is a request without a prepared batch.
func TestQuoteRejectsAnIncompleteAnswer(t *testing.T) {
	f := newFakeServer(t, "")
	c := f.client(t, Options{})
	f.handle("POST /payment/quote", jsonHandler(http.StatusOK, `{"pricing_rule":"bw-s-ceil-ms-v1","currency":"TEST","unit":"TEST units","total":"","orders":[],"errors":[]}`))
	if _, err := c.Quote(testContext(t), sampleBatch(t)); err == nil || !strings.Contains(err.Error(), "incomplete quote") {
		t.Fatalf("Quote of an incomplete answer = %v", err)
	}
	if _, err := c.Quote(testContext(t), nil); err == nil {
		t.Fatal("Quote without a batch succeeded")
	}
	if len(f.requests()) != 1 {
		t.Fatalf("%d requests, want only the first quote sent", len(f.requests()))
	}
}

// Orders sends the page selection as query parameters and refuses a page
// larger than it asked for.
func TestOrdersPagesTheHistory(t *testing.T) {
	f := newFakeServer(t, "")
	c := f.client(t, Options{})
	page := `{"intents":[{"id":"` + fixtureTx + `","method":"TEST","status":"paid","price":"40","currency":"TEST",` +
		`"pricing_rule":"","expires_at":"2026-10-05T10:00:00Z","orders":[{"order_id":0,"executor_id":"fixture-executor",` +
		`"price":"40","currency":"TEST","settlement":"pending","run_id":"` + fixtureID + `"}]}],"next":"` + fixtureTx + `"}`
	f.handle("GET /me/orders", jsonHandler(http.StatusOK, page))
	history, err := c.Orders(testContext(t), OrdersPage{Limit: 1, Before: "cursor"})
	if err != nil {
		t.Fatalf("Orders: %v", err)
	}
	if len(history.Intents) != 1 || history.Next != fixtureTx || history.Intents[0].Orders[0].RunID != fixtureID {
		t.Fatalf("history %+v", history)
	}
	if query := f.requests()[0].Query; query != "before=cursor&limit=1" {
		t.Fatalf("query %q", query)
	}
	if _, err := c.Orders(testContext(t), OrdersPage{}); err != nil {
		t.Fatalf("Orders with the default page: %v", err)
	}
	if query := f.requests()[1].Query; query != "" {
		t.Fatalf("default page query %q, want none", query)
	}
	f.handle("GET /me/orders", jsonHandler(http.StatusOK, strings.Replace(page, `"intents":[`, `"intents":[`+
		`{"id":"a","method":"TEST","status":"paid","price":"1","currency":"TEST","pricing_rule":"","expires_at":"2026-10-05T10:00:00Z","orders":[]},`, 1)))
	if _, err := c.Orders(testContext(t), OrdersPage{Limit: 1}); err == nil || !strings.Contains(err.Error(), "exceeds the requested limit") {
		t.Fatalf("Orders of an oversized page = %v", err)
	}
}

// Whoami reports the account economics of a dispatcher that states them, and
// none from one that predates them.
func TestWhoamiReportsEconomics(t *testing.T) {
	f := newFakeServer(t, "")
	c := f.client(t, Options{})
	f.handle("GET /me", jsonHandler(http.StatusOK, `{"id":"`+fixtureID+`","name":"n","role":"user",`+
		`"economics":{"payment_methods":["TEST"],"chain_payments":false,"allowances":false}}`))
	me, err := c.Whoami(testContext(t))
	if err != nil {
		t.Fatalf("Whoami: %v", err)
	}
	if !reflect.DeepEqual(me.Economics, &Economics{PaymentMethods: []string{"TEST"}}) {
		t.Fatalf("economics %+v", me.Economics)
	}
	f.handle("GET /me", jsonHandler(http.StatusOK, `{"id":"`+fixtureID+`","name":"n","role":"user"}`))
	if me, err := c.Whoami(testContext(t)); err != nil || me.Economics != nil {
		t.Fatalf("Whoami of an older dispatcher = %+v, %v", me, err)
	}
}
