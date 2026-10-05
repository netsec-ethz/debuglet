// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
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

const (
	routeQuote  = "payment/quote"
	routeOrders = "me/orders"
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
