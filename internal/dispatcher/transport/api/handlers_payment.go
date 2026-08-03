package api

import (
	"debuglet/internal/dispatcher/payments"
	"debuglet/internal/dispatcher/payments/sui"
	"math"
	"net/http"
	"strings"

	"math/big"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// TODO remove balance, replace with pay per purchase
// GET /payment/balance?address=0x...
// Requires: Authorization: Bearer <session_token>
func (h *Handler) GetBalance(c echo.Context) error {
	address := strings.ToLower(c.QueryParam("address"))
	if address == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing address")
	}
	if err := validateSuiAddress(address); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid address: "+err.Error())
	}

	authHeader := c.Request().Header.Get("Authorization")
	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok || token == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing or invalid Authorization header")
	}

	valid, err := h.database.Authenticate(address, token)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "authentication error")
	}
	if !valid {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired session")
	}

	balance, err := h.database.GetBalance(address)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch balance")
	}
	return c.JSON(http.StatusOK, BalanceResponse{Balance: int64(balance)})
}

func (h *Handler) GetPaymentIntent(c echo.Context) error {
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
	//TODO bind exact request to transaction
	_, intent, err := h.dispatcher.Payment.CreatePaymentIntent(price.Int64(), req.PaymentMethod)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "failed to create payment Intent: "+err.Error())
	}
	switch req.PaymentMethod {
	case "SUI":
		suiIntent, ok := intent.Intent.(sui.SuiPaymentIntent)
		if !ok {
			return c.JSON(http.StatusInternalServerError, "unexpected payment intent type")
		}
		return c.JSON(http.StatusOK, IntentResponse{Method: "SUI", Intent: SuiIntent{TransactionId: suiIntent.TransactionId, AuthKey: suiIntent.AuthKey, Price: suiIntent.Price, ExpiresAt: suiIntent.ExpiresAt, RegistryAddress: suiIntent.RegistryAddress, ReceiverAddress: suiIntent.ReceiverAddress}})
	case "TEST":
		dummyIntent, ok := intent.Intent.(payments.DummyIntent)
		if !ok {
			return c.JSON(http.StatusInternalServerError, "unexpected payment intent type")
		}
		return c.JSON(http.StatusOK, IntentResponse{Method: "TEST", Intent: DummyIntent{dummyIntent.TransactionId, dummyIntent.AuthKey}})
	}
	return echo.NewHTTPError(http.StatusBadRequest, "unknown payment method: "+req.PaymentMethod)
}

func (h *Handler) GetPaymentStatus(c echo.Context) error {
	transactionID := c.Param("transaction_id")
	payed, err := h.dispatcher.Payment.IsPayed(transactionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, payed)
}
