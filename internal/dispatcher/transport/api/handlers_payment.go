// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"math/big"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// paymentsDisabledMessage is the bounded JSON error message returned with HTTP
// 503 when a chain payment method is requested while Sui payments are disabled.
const paymentsDisabledMessage = "blockchain payments are disabled"

// LockPrice prices an intent and creates its Outstanding debuglet_order rows,
// returning the total price. The rows reference the intent's transaction, so
// that transaction must already exist; PutPaymentIntent therefore prices,
// creates the transaction and only then stores the orders.
// Every failure it reports is already a documented API error, so a caller can
// return it unchanged.
func (h *Handler) LockPrice(request PaymentIntentRequest, transactionId string, refundAddress string, ctx context.Context) (int64, error) {
	prices, total, err := h.priceIntent(request)
	if err != nil {
		return 0, err
	}
	if err := h.storeOrders(ctx, database.New(h.db), request, transactionId, refundAddress, prices); err != nil {
		return 0, err
	}
	return total, nil
}

// priceIntent validates and prices every debuglet of an intent without
// writing anything, returning each order's price and the total. The
// payment-mode preflight runs first so that a disabled chain method never
// reaches the executor lookup.
func (h *Handler) priceIntent(request PaymentIntentRequest) ([]int64, int64, error) {
	if err := h.dispatcher.Payment.CheckPaymentMethod(request.PaymentMethod); err != nil {
		return nil, 0, paymentMethodError(request.PaymentMethod, err)
	}
	if len(request.Debuglets) == 0 {
		return nil, 0, apiError(http.StatusBadRequest, CodeInvalidRequest, "no debuglets provided")
	}
	price := new(big.Int)
	prices := make([]int64, len(request.Debuglets))
	seen := make(map[int64]struct{}, len(request.Debuglets))
	for i, req := range request.Debuglets {
		executor, exists := h.dispatcher.GetExecutor(req.ExecutorID)
		if !exists {
			return nil, 0, apiError(http.StatusBadRequest, CodeUnknownExecutor,
				"unknown executor: "+echoed(req.ExecutorID))
		}
		if err := validatePolicy(req.OrderID, req.Policy); err != nil {
			return nil, 0, err
		}
		if _, repeated := seen[req.OrderID]; repeated {
			return nil, 0, policyError(req.OrderID, "order_id is repeated in the batch")
		}
		seen[req.OrderID] = struct{}{}

		// The price is price_per_bw_s × floor_bw × timeout_ms / 1000, exact
		// and rounded up to the next whole unit, so that a run shorter than a
		// second is not free.
		debugletPrice := new(big.Int).SetInt64(executor.PricePerBwS)
		debugletPrice.Mul(debugletPrice, big.NewInt(req.Policy.FloorBW))
		debugletPrice.Mul(debugletPrice, big.NewInt(req.Policy.TimeoutMS))
		var rem big.Int
		debugletPrice.QuoRem(debugletPrice, big.NewInt(1000), &rem)
		if rem.Sign() > 0 {
			debugletPrice.Add(debugletPrice, big.NewInt(1))
		}
		if !debugletPrice.IsInt64() {
			return nil, 0, policyError(req.OrderID, "the price of the order overflows")
		}
		prices[i] = debugletPrice.Int64()
		price.Add(price, debugletPrice)
		if !price.IsInt64() {
			return nil, 0, apiError(http.StatusBadRequest, CodeInvalidPolicy,
				"invalid policy: the total price of the batch overflows")
		}
	}
	//TODO? Add margin on price
	return prices, price.Int64(), nil
}

// storeOrders writes one Outstanding debuglet_order row per priced debuglet of
// an intent whose transaction already exists.
func (h *Handler) storeOrders(ctx context.Context, queries *database.Queries, request PaymentIntentRequest, transactionId, refundAddress string, prices []int64) error {
	for i, req := range request.Debuglets {
		h.logger.Debug("Create order", zap.String("txid", transactionId), zap.Int64("orderID", req.OrderID))
		_, err := queries.CreateDebugletOrder(ctx, database.CreateDebugletOrderParams{
			TransactionID: transactionId,
			OrderID:       req.OrderID,
			ExecutorID:    req.ExecutorID,
			Price:         prices[i],
			Currency:      request.PaymentMethod,
			RefundAddress: refundAddress,
			State:         int64(models.Outstanding),
		})
		if err != nil {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to store the order", err)
		}
	}
	return nil
}

// PUT /payment/intent
func (h *Handler) PutPaymentIntent(c echo.Context) error {

	// A payment order belongs to the account that asked for it, so the caller
	// is established before the body is read, priced or written: an
	// unauthenticated request costs no megabytes of parsing.
	established, err := requireCaller(c)
	if err != nil {
		return err
	}
	// Maintenance stops the admission of new work, and pricing new work is
	// the first half of admitting it: an intent issued now would be paid for
	// a batch this dispatcher will not accept, and the money would then have
	// to be given back. Nothing is priced, no transaction id is minted and no
	// order row is written. The check follows the caller being established,
	// so the operator's note reaches only a request that may act.
	if err := dispatcher.AdmissionPaused(); err != nil {
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, err.Error())
	}

	var req PaymentIntentRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}
	// Payment-mode preflight before the allowlist and before any transaction ID,
	// order write or intent creation: a disabled chain method (USDC or SUI) is
	// answered with 503 regardless of the HTTP allowlist below, so that the
	// disabled-mode classification does not depend on which chain methods the
	// API currently admits. Any other preflight failure (an unknown method) keeps
	// the 400 response of an invalid request.
	if err := h.dispatcher.Payment.CheckPaymentMethod(req.PaymentMethod); err != nil {
		return paymentMethodError(req.PaymentMethod, err)
	}
	// The HTTP allowlist: SUI is not admitted over the API in enabled mode.
	if (req.PaymentMethod != "TEST") && (req.PaymentMethod != "USDC") {
		return unknownPaymentMethod(req.PaymentMethod)
	}
	transactionId, err := h.dispatcher.Payment.NewTransactionID()
	//TODO ensure transactionId unique
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to generate a transaction id", err)
	}

	ctx := c.Request().Context()
	prices, price, err := h.priceIntent(req)
	if err != nil {
		// priceIntent reports documented API errors; returning the value
		// serializes the envelope instead of the error itself.
		return err
	}
	h.logger.Info("intent", zap.Int64("price", price))

	// The transaction, its orders and its owner are written together or not
	// at all: a failure part way must not leave a paid TEST transaction
	// without its orders or its owner. The transaction row comes first,
	// since the orders reference it. Nothing below may use h.db directly:
	// the pool holds one connection, and this transaction owns it.
	hash := hashDebugletRequest(req.Debuglets)
	dbTx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to begin the payment intent", err)
	}
	defer dbTx.Rollback()
	intent, err := h.dispatcher.Payment.CreatePaymentIntentIn(dbTx, transactionId, price, req.PaymentMethod, hash, ctx)
	if err != nil {
		h.logger.Info("INTENT", zap.String("hash", hash))
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to create the payment intent", err)
	}
	queries := database.New(dbTx)
	if err := h.storeOrders(ctx, queries, req, transactionId, req.RefundAddress, prices); err != nil {
		return err
	}
	// Record the owner before the intent is handed out, so that the auth key
	// this response carries can only ever be spent by the account it was
	// issued to. The local development bypass names no account and keeps the
	// ownerless behaviour it had.
	if owner, ok := established.owner(); ok {
		if err := queries.SetTransactionOwner(ctx, database.SetTransactionOwnerParams{
			TransactionID: transactionId,
			Uuid:          owner,
		}); err != nil {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to record the payment order owner", err)
		}
	}
	if err := dbTx.Commit(); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to store the payment intent", err)
	}
	switch req.PaymentMethod {
	case "USDC":
		fallthrough
	case "SUI":
		suiIntent, ok := intent.Intent.(sui.SuiPaymentIntent)
		if !ok {
			return apiError(http.StatusInternalServerError, CodeInternal, "unexpected payment intent type")
		}
		return c.JSON(http.StatusOK, IntentResponse{Method: req.PaymentMethod,
			Intent: SuiIntent{
				TransactionId:   suiIntent.TransactionId,
				AuthKey:         suiIntent.AuthKey,
				Price:           suiIntent.Price,
				CoinType:        suiIntent.CoinType,
				ExpiresAtS:      suiIntent.ExpiresAt.Unix(),
				RegistryAddress: suiIntent.RegistryAddress,
				ReceiverAddress: suiIntent.ReceiverAddress,
			}})
	case "TEST":
		dummyIntent, ok := intent.Intent.(payments.DummyIntent)
		if !ok {
			return apiError(http.StatusInternalServerError, CodeInternal, "unexpected payment intent type")
		}
		intent := DummyIntent{
			TransactionID: dummyIntent.TransactionId,
			AuthKey:       dummyIntent.AuthKey,
		}
		return c.JSON(http.StatusOK, IntentResponse{Method: "TEST", Intent: intent})
	}
	return unknownPaymentMethod(req.PaymentMethod)
}

// paymentMethodError classifies a rejected payment method: a chain method
// while blockchain payments are disabled is a temporarily unavailable
// capability, anything else is an unsupported method.
// The cause is retained so that a caller of LockPrice can still classify the
// failure with errors.Is; it is never serialized.
func paymentMethodError(method string, err error) *echo.HTTPError {
	if errors.Is(err, payments.ErrPaymentsDisabled) {
		return apiErrorFrom(http.StatusServiceUnavailable, CodePaymentsDisabled, paymentsDisabledMessage, err)
	}
	return apiErrorFrom(http.StatusBadRequest, CodeUnsupportedPaymentMethod,
		"unknown payment method: "+echoed(method), err)
}

func unknownPaymentMethod(method string) *echo.HTTPError {
	return apiError(http.StatusBadRequest, CodeUnsupportedPaymentMethod, "unknown payment method: "+echoed(method))
}

// GET /payment/:transaction_id/status
//
// GetPaymentStatus reports whether one payment order is paid. The order is
// private to the account that created it: another account's order and an
// unknown one answer alike.
func (h *Handler) GetPaymentStatus(c echo.Context) error {
	established, err := requireCaller(c)
	if err != nil {
		return err
	}
	transactionID := c.Param("transaction_id")
	if err := h.authorizeTransactionOwner(c, established, transactionID, transactionNotFound()); err != nil {
		return err
	}
	paid, err := h.dispatcher.Payment.IsPaid(c.Request().Context(), transactionID)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the payment status", err)
	}
	return c.JSON(http.StatusOK, paid)
}
