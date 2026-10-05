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

// Allowance is an account's usage allowance in TEST units: non-transferable
// usage credits an operator granted, not money. Amounts are decimal strings of
// integer TEST units. Granted is the sum of the account's grants; Consumed the
// price of its orders whose run has a settled outcome, credited or refunded
// alike; Reserved the price of the other orders of its paid intents; and
// Remaining is Granted - Consumed - Reserved.
type Allowance struct {
	Currency    string `json:"currency"`
	Granted     string `json:"granted"`
	Reserved    string `json:"reserved"`
	Consumed    string `json:"consumed"`
	Remaining   string `json:"remaining"`
	PricingRule string `json:"pricing_rule"`
}

// AllowanceGrantRequest asks for a grant to an account. Amount is a decimal
// string of TEST units; empty asks for the dispatcher's default grant. The
// idempotency key makes a repeated request issue the grant once.
type AllowanceGrantRequest struct {
	Amount         string `json:"amount,omitempty"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotency_key"`
}

// AllowanceGrant is one recorded grant. GrantedBy names the operator account
// that issued it.
type AllowanceGrant struct {
	ID             int64     `json:"id"`
	Amount         string    `json:"amount"`
	Currency       string    `json:"currency"`
	Reason         string    `json:"reason"`
	IdempotencyKey string    `json:"idempotency_key"`
	GrantedBy      string    `json:"granted_by"`
	GrantedAt      time.Time `json:"granted_at"`
}

// AllowanceGrantResult is a grant together with the account's allowance
// after it.
type AllowanceGrantResult struct {
	Grant     AllowanceGrant `json:"grant"`
	Allowance Allowance      `json:"allowance"`
}

// ExecutorEarnings is what an executor earned, as the dispatcher records it,
// and the outbound chain transfers that name the executor. Amounts are decimal
// strings of integer base units of Currency. Payouts is "enabled" or
// "disabled"; nothing is paid out while blockchain payments are disabled.
type ExecutorEarnings struct {
	Currency       string          `json:"currency"`
	TotalIncome    string          `json:"total_income"`
	CurrentBalance string          `json:"current_balance"`
	Transfers      []ChainTransfer `json:"transfers"`
	Payouts        string          `json:"payouts"`
}

// ChainTransfer is one outbound chain transfer. Kind is payout or refund;
// State is reserved, sent, confirmed, failed or unknown, where unknown means
// the outcome is not known yet, never that it failed.
type ChainTransfer struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Amount    string    `json:"amount"`
	Currency  string    `json:"currency"`
	Receiver  string    `json:"receiver"`
	State     string    `json:"state"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
