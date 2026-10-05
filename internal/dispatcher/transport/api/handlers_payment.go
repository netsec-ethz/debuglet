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
	"github.com/netsec-ethz/debuglet/pkg/wire"
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

// PricingRule names the rule priceOrder implements. A response that carries a
// price names it, so a client can tell when the rule changed between a quote
// and an intent; a different rule is a new name.
const PricingRule = "bw-s-ceil-ms-v1"

// priceIntent validates and prices every debuglet of an intent without
// writing anything, returning each order's price and the total. The
// payment-mode preflight runs first so that a disabled chain method never
// reaches the executor lookup. The first refusal priceBatch finds is the
// intent's answer.
func (h *Handler) priceIntent(request PaymentIntentRequest) ([]int64, int64, error) {
	if err := h.dispatcher.Payment.CheckPaymentMethod(request.PaymentMethod); err != nil {
		return nil, 0, paymentMethodError(request.PaymentMethod, err)
	}
	prices, total, failures := h.priceBatch(request.Debuglets)
	if len(failures) > 0 {
		return nil, 0, failures[0].err
	}
	//TODO? Add margin on price
	return prices, total, nil
}

// pricingFailure is one refusal found while pricing a batch: of the order at
// index, or of the batch as a whole when index is -1. field names the refused
// request field when the refusal does not carry its own field errors.
type pricingFailure struct {
	index int
	field string
	err   *echo.HTTPError
}

// priceBatch prices every debuglet of a batch and sums the prices. It does not
// stop at a refusal: it reports every refusal in the order it finds them, so
// the first one is what an intent answers and all of them are what a quote
// reports. prices of a refused order and total are meaningful only when
// nothing was refused.
func (h *Handler) priceBatch(debuglets []DebugletRequest) ([]int64, int64, []pricingFailure) {
	if len(debuglets) == 0 {
		return nil, 0, []pricingFailure{{index: -1, field: "debuglets",
			err: apiError(http.StatusBadRequest, CodeInvalidRequest, "no debuglets provided")}}
	}
	var failures []pricingFailure
	total := new(big.Int)
	overflowed := false
	prices := make([]int64, len(debuglets))
	seen := make(map[int64]struct{}, len(debuglets))
	for i, req := range debuglets {
		price, err := h.priceOrder(req)
		if err != nil {
			failures = append(failures, pricingFailure{index: i, err: err})
		}
		if _, repeated := seen[req.OrderID]; repeated {
			failures = append(failures, pricingFailure{index: i, field: "order_id",
				err: policyError(req.OrderID, "order_id is repeated in the batch")})
			continue
		}
		seen[req.OrderID] = struct{}{}
		if err != nil {
			continue
		}
		prices[i] = price
		total.Add(total, big.NewInt(price))
		if !total.IsInt64() && !overflowed {
			overflowed = true
			failures = append(failures, pricingFailure{index: -1, field: "debuglets",
				err: apiError(http.StatusBadRequest, CodeInvalidPolicy,
					"invalid policy: the total price of the batch overflows")})
		}
	}
	if len(failures) > 0 {
		return prices, 0, failures
	}
	return prices, total.Int64(), nil
}

// priceOrder validates one debuglet of a batch and prices it with the
// executor's announced rate. It is the only place a price is computed.
func (h *Handler) priceOrder(req DebugletRequest) (int64, *echo.HTTPError) {
	if _, err := submittedConfiguration(req); err != nil {
		return 0, apiError(http.StatusBadRequest, CodeInvalidRequest, err.Error())
	}
	executor, exists := h.dispatcher.GetExecutor(req.ExecutorID)
	if !exists {
		return 0, apiError(http.StatusBadRequest, CodeUnknownExecutor,
			"unknown executor: "+echoed(req.ExecutorID))
	}
	if err := validatePolicy(req.OrderID, req.Policy); err != nil {
		return 0, err
	}

	// The price is price_per_bw_s × floor_bw × timeout_ms / 1000, exact
	// and rounded up to the next whole unit, so that a run shorter than a
	// second is not free.
	price := new(big.Int).SetInt64(executor.PricePerBwS)
	price.Mul(price, big.NewInt(req.Policy.FloorBW))
	price.Mul(price, big.NewInt(req.Policy.TimeoutMS))
	var rem big.Int
	price.QuoRem(price, big.NewInt(1000), &rem)
	if rem.Sign() > 0 {
		price.Add(price, big.NewInt(1))
	}
	if !price.IsInt64() {
		return 0, policyError(req.OrderID, "the price of the order overflows")
	}
	return price.Int64(), nil
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
	var req PaymentIntentRequest
	if err := h.allowAdmissionRequest(c, established); err != nil {
		return err
	}
	if err := decodeMeasurementRequest(c, &req); err != nil {
		return err
	}
	if err := validateUploadBatch(req.Debuglets); err != nil {
		return err
	}
	if req.Retry != nil {
		if err := h.authorizeRetry(c, req.Retry, len(req.Debuglets)); err != nil {
			return err
		}
		if saved, err := h.readRetryIntent(c.Request().Context(), database.New(h.db), established, req); err != nil {
			return err
		} else if saved != nil {
			return c.JSON(http.StatusOK, saved)
		}
	}
	if err := dispatcher.AdmissionPaused(); err != nil {
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, err.Error())
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
	hash := submissionHash(req.Debuglets, req.Retry)
	dbTx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to begin the payment intent", err)
	}
	defer dbTx.Rollback()
	queries := database.New(dbTx)
	if req.Retry != nil {
		if saved, err := h.readRetryIntent(ctx, queries, established, req); err != nil {
			return err
		} else if saved != nil {
			_ = dbTx.Rollback()
			return c.JSON(http.StatusOK, saved)
		}
	}
	intent, err := h.dispatcher.Payment.CreatePaymentIntentIn(dbTx, transactionId, price, req.PaymentMethod, hash, ctx)
	if err != nil {
		h.logger.Info("INTENT", zap.String("hash", hash))
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to create the payment intent", err)
	}
	if err := queries.SetTransactionPricingRule(ctx, database.SetTransactionPricingRuleParams{
		PricingRule: PricingRule, ID: transactionId,
	}); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to record the pricing rule", err)
	}
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
	response, err := paymentIntentResponse(req.PaymentMethod, intent)
	if err != nil {
		return err
	}
	// The stored prices, stated as the quote of the same batch would state
	// them, so a client can compare the two exactly.
	quote := newQuote(req.PaymentMethod, req.Debuglets, prices, price, nil)
	response.Quote = &quote
	if req.Retry != nil {
		if err := storeRetryIntent(ctx, queries, established, req, transactionId, response); err != nil {
			return err
		}
		response.Retry = &wire.RetryReceipt{RetryLink: *req.Retry}
	}
	if err := dbTx.Commit(); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to store the payment intent", err)
	}
	return c.JSON(http.StatusOK, response)
}

func paymentIntentResponse(method string, intent payments.PaymentIntent) (IntentResponse, error) {
	switch method {
	case "USDC", "SUI":
		suiIntent, ok := intent.Intent.(sui.SuiPaymentIntent)
		if !ok {
			return IntentResponse{}, apiError(http.StatusInternalServerError, CodeInternal, "unexpected payment intent type")
		}
		return IntentResponse{Method: method, Intent: SuiIntent{
			TransactionId: suiIntent.TransactionId, AuthKey: suiIntent.AuthKey, Price: suiIntent.Price,
			CoinType: suiIntent.CoinType, ExpiresAtS: suiIntent.ExpiresAt.Unix(),
			RegistryAddress: suiIntent.RegistryAddress, ReceiverAddress: suiIntent.ReceiverAddress,
		}}, nil
	case "TEST":
		dummy, ok := intent.Intent.(payments.DummyIntent)
		if !ok {
			return IntentResponse{}, apiError(http.StatusInternalServerError, CodeInternal, "unexpected payment intent type")
		}
		return IntentResponse{Method: method, Intent: DummyIntent{TransactionID: dummy.TransactionId, AuthKey: dummy.AuthKey}}, nil
	default:
		return IntentResponse{}, unknownPaymentMethod(method)
	}
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
