package api

import (
	"context"
	"debuglet/internal/dispatcher/database/ddb"
	"debuglet/internal/dispatcher/payments"
	"debuglet/internal/dispatcher/payments/sui"
	"math"
	"net/http"

	"fmt"
	"math/big"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

func (h *Handler) LockPrice(request PaymentIntentRequest, transactionId string, ctx context.Context) (int64, error) {
	queries := ddb.New(h.dispatcher.DB())
	price := new(big.Int).SetInt64(0)
	for _, req := range request.Debuglets {
		executor, exists := h.dispatcher.GetExecutor(req.ExecutorID)
		if !exists {
			return 0, fmt.Errorf("Executor does not exists: %w", req.ExecutorID)
		}
		if req.Policy.TimeoutMS < 0 || req.Policy.FloorBW < 0 || req.Policy.CeilBW < req.Policy.FloorBW {
			return 0, fmt.Errorf("Invalid request. Timeout and FloorBW must be poisitive. CeilBW must be at least FloorBW")
		}

		ppb := new(big.Int).SetInt64(executor.PricePerBwS)
		floorBW := new(big.Int).SetInt64(req.Policy.FloorBW)
		timeout := new(big.Int).SetInt64(req.Policy.TimeoutMS / 1000)
		debugletPrice := new(big.Int).Mul(new(big.Int).Mul(ppb, floorBW), timeout)

		queries.CreateDebugletOrder(ctx, ddb.CreateDebugletOrderParams{
			TransactionID: transactionId,
			OrderID:       req.OrderID,
			ExecutorID:    req.ExecutorID,
			Price:         debugletPrice.Int64(),
			Currency:      executor.Currency,
		})

		price.Add(price, debugletPrice)
	}
	//TODO? Add margin on price
	if price.Cmp(new(big.Int).SetInt64(math.MaxInt64)) == 1 {
		return 0, fmt.Errorf("Invalid Request - Price overflowed")
	}
	return price.Int64(), nil
}

// PUT /payment/intent
func (h *Handler) PutPaymentIntent(c echo.Context) error {

	var req PaymentIntentRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}
	if (req.PaymentMethod != "SUI") && (req.PaymentMethod != "TEST") && (req.PaymentMethod != "USDC") {
		return c.JSON(http.StatusBadRequest, "unknown payment method: "+req.PaymentMethod)
	}
	transactionId, err := h.dispatcher.Payment.NewTransactionID()
	//TODO ensure transactionId unique
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "failed to generate id")
	}

	ctx := c.Request().Context()
	price, err := h.LockPrice(req, transactionId, ctx)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	h.logger.Info("intent", zap.Int64("price", price))

	hash := hashDebugletRequest(req.Debuglets)
	intent, err := h.dispatcher.Payment.CreatePaymentIntent(transactionId, price, req.PaymentMethod, hash, c.Request().Context())
	if err != nil {
		h.logger.Info("INTENT", zap.String("hash", hash), zap.String("err", err.Error()))
		return c.JSON(http.StatusInternalServerError, "failed to create payment Intent: "+err.Error())
	}
	switch req.PaymentMethod {
	case "USDC":
		fallthrough
	case "SUI":
		suiIntent, ok := intent.Intent.(sui.SuiPaymentIntent)
		if !ok {
			return c.JSON(http.StatusInternalServerError, "unexpected payment intent type")
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
			return c.JSON(http.StatusInternalServerError, "unexpected payment intent type")
		}
		intent := DummyIntent{
			TransactionID: dummyIntent.TransactionId,
			AuthKey:       dummyIntent.AuthKey,
		}
		return c.JSON(http.StatusOK, IntentResponse{Method: "TEST", Intent: intent})
	}
	return echo.NewHTTPError(http.StatusBadRequest, "unknown payment method: "+req.PaymentMethod)
}

// GET /payment/:transaction_id/status
func (h *Handler) GetPaymentStatus(c echo.Context) error {
	transactionID := c.Param("transaction_id")
	paid, err := h.dispatcher.Payment.IsPaid(c.Request().Context(), transactionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, paid)
}
