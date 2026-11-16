// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
)

type prepaidDepositResponse struct {
	TransactionID string `json:"transaction_id"`
	Amount        string `json:"amount"`
	Status        string `json:"status"`
	Digest        string `json:"digest,omitempty"`
}

func (h *Handler) GetPersonalWallet(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	currency := c.QueryParam("currency")
	if currency == "" {
		currency = "SUI"
	}
	budget, err := h.dispatcher.Payment.PersonalBalance(c.Request().Context(), h.db, account.UserUUID, currency)
	if err != nil {
		return communityFundingError(err)
	}
	_, network := h.dispatcher.Payment.CommunityCurrency()
	rows, err := h.db.QueryContext(c.Request().Context(), `SELECT t.id,t.price,t.status,COALESCE((SELECT r.tx_digest FROM payment_receipts r WHERE r.nonce=t.id AND r.disposition='applied' LIMIT 1),'') FROM prepaid_topups d JOIN transactions t ON t.id=d.transaction_id JOIN users u ON u.id=d.user_id WHERE u.uuid=? AND d.purpose='personal' AND d.network=? ORDER BY t.expires_at DESC LIMIT 50`, account.UserUUID, network)
	if err != nil {
		return communityFundingError(err)
	}
	defer rows.Close()
	deposits := make([]prepaidDepositResponse, 0)
	for rows.Next() {
		var d prepaidDepositResponse
		var amount, status int64
		if err := rows.Scan(&d.TransactionID, &amount, &status, &d.Digest); err != nil {
			return communityFundingError(err)
		}
		d.Amount = strconv.FormatInt(amount, 10)
		d.Status = intentStatus(status)
		deposits = append(deposits, d)
	}
	if err := rows.Err(); err != nil {
		return communityFundingError(err)
	}
	return c.JSON(http.StatusOK, struct {
		communityWalletResponse
		Deposits []prepaidDepositResponse `json:"deposits"`
	}{communityWalletResponse: communityWalletResponse{Mode: "prepaid", Currency: currency, Unit: currencyUnit(currency), Network: network, Enabled: true,
		Funded: strconv.FormatInt(budget.Funded, 10), Reserved: strconv.FormatInt(budget.Reserved, 10), Spent: strconv.FormatInt(budget.Spent, 10), Available: strconv.FormatInt(budget.Available, 10)}, Deposits: deposits})
}

func (h *Handler) CreatePersonalTopUp(c echo.Context) error {
	return h.createPrepaidTopUp(c, "personal")
}
func (h *Handler) CreateHostingTopUp(c echo.Context) error {
	if _, err := requireOperator(c); err != nil {
		return err
	}
	return h.createPrepaidTopUp(c, "hosting")
}
func (h *Handler) createPrepaidTopUp(c echo.Context, purpose string) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if err := h.allowAdmissionRequest(c, account); err != nil {
		return err
	}
	var request struct {
		Amount        string `json:"amount"`
		RefundAddress string `json:"refund_address"`
		Key           string `json:"idempotency_key"`
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 1024)
	if err := decodeMeasurementRequest(c, &request); err != nil {
		return err
	}
	amount, err := strconv.ParseInt(request.Amount, 10, 64)
	if err != nil || amount <= 0 || amount > 1<<53-1 || strconv.FormatInt(amount, 10) != request.Amount || len(request.Key) < 1 || len(request.Key) > 128 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "amount must be a positive integer MIST string and idempotency_key must contain 1 to 128 characters")
	}
	if err := sui.ValidAddress(request.RefundAddress); err != nil {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "refund_address must be a Sui address")
	}
	id, err := h.dispatcher.Payment.NewTransactionID()
	if err != nil {
		return communityFundingError(err)
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return communityFundingError(err)
	}
	defer tx.Rollback()
	intent, err := h.dispatcher.Payment.CreatePrepaidTopUpIn(ctx, tx, account.UserUUID, id, request.Key, purpose, amount, request.RefundAddress)
	if err != nil {
		return communityFundingError(err)
	}
	response, err := paymentIntentResponse("SUI", intent)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return communityFundingError(err)
	}
	return c.JSON(http.StatusCreated, response)
}
