// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "time"

// Quote is the price of a batch as the dispatcher's pricing authority computes
// it, without reserving anything. Amounts are decimal strings of integer base
// units of Currency, described by Unit. Total is empty unless every order was
// priced; Errors then lists the problems of the batch as a whole and each
// QuotedOrder its own.
type Quote struct {
	PricingRule string        `json:"pricing_rule"`
	Currency    string        `json:"currency"`
	Unit        string        `json:"unit"`
	Total       string        `json:"total"`
	Orders      []QuotedOrder `json:"orders"`
	Errors      []FieldError  `json:"errors"`
}

// QuotedOrder is one order of a Quote, in request order. Price is empty when
// the order could not be priced, and Errors states why.
type QuotedOrder struct {
	OrderID    int64        `json:"order_id"`
	ExecutorID string       `json:"executor_id"`
	Price      string       `json:"price"`
	Errors     []FieldError `json:"errors"`
}

// Economics states which payment features this dispatcher offers the account,
// so a client can hide what is unavailable. It reports configuration, not a
// balance.
type Economics struct {
	PaymentMethods []string `json:"payment_methods"`
	ChainPayments  bool     `json:"chain_payments"`
	Allowances     bool     `json:"allowances"`
}

// OrderHistory is one page of the account's payment intents, newest expiry
// first. Next is the cursor of the following page, empty on the last one.
type OrderHistory struct {
	Intents []OrderHistoryIntent `json:"intents"`
	Next    string               `json:"next"`
}

// OrderHistoryIntent is one payment intent with its orders. Status is one of
// outstanding, paid, refunded, expired or aborted, or unknown for a value
// this version does not name. PricingRule is empty when the dispatcher did not
// record the rule the intent was priced with.
type OrderHistoryIntent struct {
	ID          string              `json:"id"`
	Method      string              `json:"method"`
	Status      string              `json:"status"`
	Price       string              `json:"price"`
	Currency    string              `json:"currency"`
	PricingRule string              `json:"pricing_rule"`
	ExpiresAt   time.Time           `json:"expires_at"`
	Orders      []OrderHistoryOrder `json:"orders"`
}

// OrderHistoryOrder is one order of an intent. Settlement is pending,
// credited or refunded, as in RunCost. RunID names the admitted run and is
// empty while the order has not been admitted.
type OrderHistoryOrder struct {
	OrderID    int64  `json:"order_id"`
	ExecutorID string `json:"executor_id"`
	Price      string `json:"price"`
	Currency   string `json:"currency"`
	Settlement string `json:"settlement"`
	RunID      string `json:"run_id,omitempty"`
}
