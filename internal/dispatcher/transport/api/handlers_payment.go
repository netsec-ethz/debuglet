package api

import (
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

/*
func (h *Handler) GetIntent(c echo.Context) error {
	transactionId := make([]byte, 16)
	authKey := make([]byte, 16)
	_, err := rand.Read(transactionId)
	_, err2 := rand.Read(authKey)
	if err != nil || err2 != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create intent")
	}
	expiresAt := time.Now().Add(time.Minute * 5).Unix()
	h.transactionDB.StoreTransaction(hex.EncodeToString(transactionId), hex.EncodeToString(authKey), expiresAt)

	return c.JSON(http.StatusOK, IntentResponse{Method: "SUI", Intent: SuiIntent{transactionId, authKey, expiresAt}})
}
*/
