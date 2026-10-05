// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/wire"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// maxOrderHistoryPage bounds one page of GET /me/orders.
const maxOrderHistoryPage = 100

// POST /payment/quote
//
// PostPaymentQuote prices a batch as PUT /payment/intent would, and stops
// there: it writes nothing, creates no transaction and issues no auth key. A
// batch the intent would refuse is still quoted, with the refusals in its
// errors; only a request the intent could not even read keeps the intent's
// status. The intent prices again when it is created.
func (h *Handler) PostPaymentQuote(c echo.Context) error {
	established, err := requireCaller(c)
	if err != nil {
		return err
	}
	if err := h.allowAdmissionRequest(c, established); err != nil {
		return err
	}
	var req PaymentIntentRequest
	if err := decodeMeasurementRequest(c, &req); err != nil {
		return err
	}
	if err := validateUploadBatch(req.Debuglets); err != nil {
		return err
	}
	if err := h.dispatcher.Payment.CheckPaymentMethod(req.PaymentMethod); err != nil {
		return paymentMethodError(req.PaymentMethod, err)
	}
	if req.PaymentMethod != "TEST" && req.PaymentMethod != "USDC" {
		return unknownPaymentMethod(req.PaymentMethod)
	}
	prices, total, failures := h.priceBatch(req.Debuglets)
	return c.JSON(http.StatusOK, newQuote(req.PaymentMethod, req.Debuglets, prices, total, failures))
}

// newQuote states the prices of a batch, and the refusals found while pricing
// it, in the shape of wire.Quote. The total is reported only when every order
// was priced.
func newQuote(method string, debuglets []DebugletRequest, prices []int64, total int64, failures []pricingFailure) wire.Quote {
	quote := wire.Quote{
		PricingRule: PricingRule,
		Currency:    method,
		Unit:        currencyUnit(method),
		Orders:      make([]wire.QuotedOrder, len(debuglets)),
		Errors:      []wire.FieldError{},
	}
	for i, req := range debuglets {
		quote.Orders[i] = wire.QuotedOrder{OrderID: req.OrderID, ExecutorID: req.ExecutorID, Errors: []wire.FieldError{}}
	}
	for _, failure := range failures {
		if failure.index < 0 {
			quote.Errors = append(quote.Errors, quoteFieldErrors(failure, nil)...)
			continue
		}
		orderID := debuglets[failure.index].OrderID
		order := &quote.Orders[failure.index]
		order.Errors = append(order.Errors, quoteFieldErrors(failure, &orderID)...)
	}
	for i := range quote.Orders {
		if len(quote.Orders[i].Errors) == 0 {
			quote.Orders[i].Price = strconv.FormatInt(prices[i], 10)
		}
	}
	if len(failures) == 0 {
		quote.Total = strconv.FormatInt(total, 10)
	}
	return quote
}

// quoteFieldErrors states one pricing refusal as field errors. A refusal that
// names its fields keeps them; any other names the field its failure concerns,
// with the code and message the intent would answer.
func quoteFieldErrors(failure pricingFailure, orderID *int64) []wire.FieldError {
	body, _ := failure.err.Message.(ErrorResponse)
	if len(body.FieldErrors) > 0 {
		return body.FieldErrors
	}
	field := failure.field
	if field == "" {
		switch body.Code {
		case CodeUnknownExecutor:
			field = "executor_id"
		case CodeInvalidPolicy:
			field = "policy"
		}
	}
	return []wire.FieldError{{Field: field, Code: body.Code, Message: body.Message, OrderID: orderID}}
}

// currencyUnit names the base unit amounts of currency are counted in.
func currencyUnit(currency string) string {
	switch currency {
	case "TEST":
		return "TEST units"
	case "USDC":
		return "micro-USDC"
	default:
		return "base units"
	}
}

// orderSettlement reports what became of an order's reserved price, as
// RunCost.Settlement does.
func orderSettlement(state int64) string {
	switch models.TransactionState(state) {
	case models.Credited:
		return "credited"
	case models.Refunded:
		return "refunded"
	default:
		return "pending"
	}
}

// intentStatus names the state of a payment intent.
func intentStatus(state int64) string {
	switch models.TransactionState(state) {
	case models.Outstanding:
		return "outstanding"
	case models.Paid:
		return "paid"
	case models.Refunded:
		return "refunded"
	case models.Expired:
		return "expired"
	case models.Aborted:
		return "aborted"
	default:
		return "unknown"
	}
}

// accountEconomics reports the payment features this dispatcher offers now.
// A chain method is offered exactly when the payment preflight admits it.
func (h *Handler) accountEconomics() *wire.Economics {
	economics := &wire.Economics{PaymentMethods: []string{"TEST"}}
	if h.dispatcher.Payment.CheckPaymentMethod("USDC") == nil {
		economics.PaymentMethods = append(economics.PaymentMethods, "USDC")
		economics.ChainPayments = true
	}
	return economics
}

// GET /me/orders?limit=&before=
//
// GetMyOrders pages the caller's own payment intents with their orders,
// newest expiry first. There is no creation time on an intent; its expiry is
// creation plus a fixed period, so the order is the order of creation. before
// is the next cursor of the previous page.
func (h *Handler) GetMyOrders(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	limit, err := pageNumber(c, "limit", 25, maxOrderHistoryPage)
	if err != nil {
		return err
	}
	if limit == 0 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "limit must be positive")
	}
	before := c.QueryParam("before")
	if len(before) > 64 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "before must be a cursor returned as next")
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return orderHistoryFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	// One row beyond the page tells whether another page follows.
	rows, err := q.ListAccountIntents(ctx, database.ListAccountIntentsParams{UserUuid: caller.UserUUID, Before: before, PageLimit: limit + 1})
	if err != nil {
		return orderHistoryFailure(err)
	}
	page := wire.OrderHistory{Intents: make([]wire.OrderHistoryIntent, 0, min(int64(len(rows)), limit))}
	if int64(len(rows)) > limit {
		rows = rows[:limit]
		page.Next = rows[limit-1].ID
	}
	for _, row := range rows {
		orders, err := q.ListIntentOrders(ctx, row.ID)
		if err != nil {
			return orderHistoryFailure(err)
		}
		intent := wire.OrderHistoryIntent{
			ID: row.ID, Method: row.Method, Status: intentStatus(row.Status),
			Price: strconv.FormatInt(row.Price, 10), Currency: row.Currency, PricingRule: row.PricingRule,
			ExpiresAt: row.ExpiresAt.UTC(), Orders: make([]wire.OrderHistoryOrder, 0, len(orders)),
		}
		for _, order := range orders {
			entry := wire.OrderHistoryOrder{
				OrderID: order.OrderID, ExecutorID: order.ExecutorID,
				Price: strconv.FormatInt(order.Price, 10), Currency: order.Currency,
				Settlement: orderSettlement(order.State),
			}
			if order.RunID != uuid.Nil {
				entry.RunID = order.RunID.String()
			}
			intent.Orders = append(intent.Orders, entry)
		}
		page.Intents = append(page.Intents, intent)
	}
	if err := tx.Commit(); err != nil {
		return orderHistoryFailure(err)
	}
	return c.JSON(http.StatusOK, page)
}

func orderHistoryFailure(err error) error {
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to load the order history", err)
}
