package api

import (
	"debuglet/internal/dispatcher/payments"
	"debuglet/internal/dispatcher/payments/sui"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
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
	price := int64(0)
	for _, req := range req.Debuglets {
		executor, exists := h.dispatcher.GetExecutor(req.ExecutorID)
		if !exists {
			return c.JSON(http.StatusBadRequest, "Executor does not exists: "+req.ExecutorID)
		}
		//TODO guard against overflow
		price += int64(executor.PricePerBw) * req.Policy.FloorBW * req.Policy.TimeoutMS
	}
	//TODO bind request to transaction
	_, intent, err := h.dispatcher.Payment.CreatePaymentIntent(price, req.PaymentMethod)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "failed to create payment Intent: "+err.Error())
	}
	switch req.PaymentMethod {
	case "SUI":
		suiIntent, ok := intent.Intent.(sui.SuiPaymentIntent)
		if !ok {
			return c.JSON(http.StatusInternalServerError, "unexpected payment intent type")
		}
		return c.JSON(http.StatusOK, IntentResponse{Method: "SUI", Intent: SuiIntent{suiIntent.TransactionId, suiIntent.AuthKey, suiIntent.ExpiresAt, ""}})
	case "TEST":
		dummyIntent, ok := intent.Intent.(payments.DummyIntent)
		if !ok {
			return c.JSON(http.StatusInternalServerError, "unexpected payment intent type")
		}
		return c.JSON(http.StatusOK, IntentResponse{Method: "TEST", Intent: DummyIntent{dummyIntent.TransactionId, dummyIntent.AuthKey}})
	}
	return echo.NewHTTPError(http.StatusBadRequest, "unknown payment method: "+req.PaymentMethod)
}
