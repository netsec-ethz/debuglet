package api

import (
	"debuglet/internal/dispatcher/payments"
	"debuglet/internal/dispatcher/payments/sui"
	"math"
	"net/http"

	"math/big"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// PUT /payment/intent
func (h *Handler) PutPaymentIntent(c echo.Context) error {
	var req PaymentIntentRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}
	if (req.PaymentMethod != "SUI") && (req.PaymentMethod != "TEST") {
		return c.JSON(http.StatusBadRequest, "unknown payment method: "+req.PaymentMethod)
	}
	price := new(big.Int).SetInt64(0)
	for _, req := range req.Debuglets {
		executor, exists := h.dispatcher.GetExecutor(req.ExecutorID)
		if !exists {
			return c.JSON(http.StatusBadRequest, "Executor does not exists: "+req.ExecutorID)
		}
		if req.Policy.TimeoutMS < 0 || req.Policy.FloorBW < 0 {
			return c.JSON(http.StatusBadRequest, "Invalid request")
		}

		ppb := new(big.Int).SetInt64(executor.PricePerBw)
		floorBW := new(big.Int).SetInt64(req.Policy.FloorBW)
		timeout := new(big.Int).SetInt64(req.Policy.TimeoutMS / 1000)
		price.Add(price, new(big.Int).Mul(new(big.Int).Mul(ppb, floorBW), timeout))
	}
	if price.Cmp(new(big.Int).SetInt64(math.MaxInt64)) == 1 {
		return c.JSON(http.StatusBadRequest, "Price exceeds upper limit")
	}
	h.logger.Info("intent", zap.Int64("price", price.Int64()))
	// TODO: bind exact request to transaction
	hash := hashDebugletRequest(req.Debuglets)
	intent, err := h.dispatcher.Payment.CreatePaymentIntent(c.Request().Context(), price.Int64(), req.PaymentMethod, hash)
	if err != nil {
		h.logger.Info("INTENT", zap.String("hash", hash), zap.String("err", err.Error()))
		return c.JSON(http.StatusInternalServerError, "failed to create payment Intent: "+err.Error())
	}
	switch req.PaymentMethod {
	case "SUI":
		suiIntent, ok := intent.Intent.(sui.SuiPaymentIntent)
		if !ok {
			return c.JSON(http.StatusInternalServerError, "unexpected payment intent type")
		}
		return c.JSON(http.StatusOK, IntentResponse{Method: "SUI",
			Intent: SuiIntent{
				TransactionId:   suiIntent.TransactionId,
				AuthKey:         suiIntent.AuthKey,
				Price:           suiIntent.Price,
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
