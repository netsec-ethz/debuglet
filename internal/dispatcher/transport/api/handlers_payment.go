package api

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

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
