// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// Quote is the dispatcher's price of a batch; see Client.Quote.
type Quote = wire.Quote

// Economics reports the payment features a dispatcher offers an account, as
// User.Economics.
type Economics = wire.Economics

// OrderHistory is one page of Client.Orders.
type OrderHistory = wire.OrderHistory

// Allowance is the account's usage allowance; see Client.Allowance.
type Allowance = wire.Allowance

// ExecutorEarnings is an owned executor's earnings; see
// Client.ExecutorEarnings.
type ExecutorEarnings = wire.ExecutorEarnings

const (
	routeQuote     = "payment/quote"
	routeOrders    = "me/orders"
	routeAllowance = "me/allowance"
	// economicsAPIVersion is the first contract version with quotes and the
	// order history.
	economicsAPIVersion = "1.15"
)

// OrdersPage selects one page of Client.Orders. A zero Limit asks for the
// server's default page size; Before is the Next value of the previous page.
type OrdersPage struct {
	Limit  int64
	Before string
}

// Quote asks the dispatcher to price batch with the same TEST request body
// SubmitTEST would send, without creating an intent. A batch the dispatcher
// would refuse is answered with its problems in the quote's errors and an
// empty total. Submission prices the batch again, so compare the quote with
// the quote the intent returns.
func (c *Client) Quote(ctx context.Context, batch *PreparedBatch) (Quote, error) {
	if batch == nil || batch.count == 0 || len(batch.debuglets) == 0 {
		return Quote{}, errInvalidBatch
	}
	ctx = context.WithValue(ctx, requiredVersionKey{}, economicsAPIVersion)
	data, err := c.doWithLimit(ctx, http.MethodPost, routeQuote, nil, intentEnvelope(batch.debuglets), http.StatusOK, maxSuccessBody)
	if err != nil {
		return Quote{}, err
	}
	var quote Quote
	if err := c.decode(http.MethodPost, routeQuote, data, &quote); err != nil {
		return Quote{}, err
	}
	if quote.PricingRule == "" || len(quote.Orders) != batch.count {
		return Quote{}, c.protocolErr(http.MethodPost, routeQuote, "incomplete quote")
	}
	return quote, nil
}

// Orders returns one page of the authenticated account's payment intents,
// newest first, with their orders and the runs they admitted.
func (c *Client) Orders(ctx context.Context, page OrdersPage) (OrderHistory, error) {
	ctx = context.WithValue(ctx, requiredVersionKey{}, economicsAPIVersion)
	query := url.Values{}
	if page.Limit != 0 {
		query.Set("limit", strconv.FormatInt(page.Limit, 10))
	}
	if page.Before != "" {
		query.Set("before", page.Before)
	}
	data, err := c.doWithLimit(ctx, http.MethodGet, routeOrders, query, nil, http.StatusOK, maxSuccessBody)
	if err != nil {
		return OrderHistory{}, err
	}
	var history OrderHistory
	if err := c.decode(http.MethodGet, routeOrders, data, &history); err != nil {
		return OrderHistory{}, err
	}
	if page.Limit > 0 && int64(len(history.Intents)) > page.Limit {
		return OrderHistory{}, c.protocolErr(http.MethodGet, routeOrders, "page exceeds the requested limit")
	}
	return history, nil
}

// Allowance returns the authenticated account's usage allowance in TEST units.
// A dispatcher that does not offer allowances answers 404 with not_found;
// User.Economics.Allowances tells beforehand.
func (c *Client) Allowance(ctx context.Context) (Allowance, error) {
	ctx = context.WithValue(ctx, requiredVersionKey{}, economicsAPIVersion)
	data, err := c.do(ctx, http.MethodGet, routeAllowance, nil, nil, http.StatusOK)
	if err != nil {
		return Allowance{}, err
	}
	var allowance Allowance
	if err := c.decode(http.MethodGet, routeAllowance, data, &allowance); err != nil {
		return Allowance{}, err
	}
	if allowance.Currency == "" || allowance.Remaining == "" {
		return Allowance{}, c.protocolErr(http.MethodGet, routeAllowance, "incomplete allowance")
	}
	return allowance, nil
}

// ExecutorEarnings returns what an executor the authenticated account owns
// has earned and the outbound chain transfers that name it. Another account's
// executor answers 404 with not_found.
func (c *Client) ExecutorEarnings(ctx context.Context, executorID string) (ExecutorEarnings, error) {
	if executorID == "" {
		return ExecutorEarnings{}, errors.New("client: an executor ID is required")
	}
	ctx = context.WithValue(ctx, requiredVersionKey{}, economicsAPIVersion)
	route := "operator/executors/" + url.PathEscape(executorID) + "/earnings"
	data, err := c.do(ctx, http.MethodGet, route, nil, nil, http.StatusOK)
	if err != nil {
		return ExecutorEarnings{}, err
	}
	var earnings ExecutorEarnings
	if err := c.decode(http.MethodGet, route, data, &earnings); err != nil {
		return ExecutorEarnings{}, err
	}
	if earnings.Payouts == "" {
		return ExecutorEarnings{}, c.protocolErr(http.MethodGet, route, "incomplete earnings")
	}
	return earnings, nil
}
