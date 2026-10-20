// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/studio"
)

func (h *Handler) registerCommunityFundingRoutes(e *echo.Echo) {
	e.GET("/communities/:id/wallet", h.GetCommunityWallet)
	e.POST("/communities/:id/wallet/top-ups", h.CreateCommunityTopUp)
}

type communityWalletResponse struct {
	Mode      string `json:"mode"`
	Currency  string `json:"currency"`
	Unit      string `json:"unit"`
	Network   string `json:"network"`
	Enabled   bool   `json:"enabled"`
	Funded    string `json:"funded"`
	Reserved  string `json:"reserved"`
	Spent     string `json:"spent"`
	Available string `json:"available"`
}

func communityFundingError(err error) error {
	var insufficient *payments.CommunityFundsError
	var allowance *payments.AllowanceExceededError
	switch {
	case errors.Is(err, payments.ErrCommunityNotFound):
		return communityNotFound()
	case errors.Is(err, payments.ErrCommunityOwner):
		return apiError(http.StatusForbidden, CodeForbidden, err.Error())
	case errors.Is(err, payments.ErrCommunityAllowanceDisabled):
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, err.Error())
	case errors.Is(err, payments.ErrCommunityNetwork):
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, err.Error())
	case errors.Is(err, payments.ErrCommunityDeposit):
		return apiError(http.StatusBadRequest, CodeInvalidRequest, err.Error())
	case errors.As(err, &insufficient):
		return apiError(http.StatusConflict, CodeInvalidRequest, err.Error())
	case errors.As(err, &allowance):
		return allowanceExceeded(allowance)
	case errors.Is(err, payments.ErrPaymentsDisabled):
		return paymentMethodError("USDC", err)
	default:
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "community funding failed", err)
	}
}

func (h *Handler) GetCommunityWallet(c echo.Context) error {
	if _, err := h.requireCommunity(c, c.Param("id"), false); err != nil {
		return err
	}
	currency, network := h.dispatcher.Payment.CommunityCurrency()
	tx, err := h.db.BeginTx(c.Request().Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return communityFundingError(err)
	}
	defer tx.Rollback()
	budget, err := h.dispatcher.Payment.CommunityBalance(c.Request().Context(), tx, c.Param("id"), currency)
	enabled := !errors.Is(err, payments.ErrCommunityAllowanceDisabled)
	if err != nil && enabled {
		return communityFundingError(err)
	}
	response := communityWalletResponse{Mode: currency, Currency: currency, Unit: currencyUnit(currency), Network: network, Enabled: enabled,
		Funded: strconv.FormatInt(budget.Funded, 10), Reserved: strconv.FormatInt(budget.Reserved, 10),
		Spent: strconv.FormatInt(budget.Spent, 10), Available: strconv.FormatInt(budget.Available, 10)}
	if currency == "TEST" {
		response.Unit = "TEST"
	}
	return c.JSON(http.StatusOK, response)
}

func (h *Handler) CreateCommunityTopUp(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if _, err := h.requireCommunity(c, c.Param("id"), false); err != nil {
		return err
	}
	if err := h.allowAdmissionRequest(c, account); err != nil {
		return err
	}
	var request struct {
		Amount        string `json:"amount"`
		RefundAddress string `json:"refund_address"`
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 1024)
	if err := decodeMeasurementRequest(c, &request); err != nil {
		return err
	}
	amount, err := strconv.ParseInt(request.Amount, 10, 64)
	if err != nil || amount <= 0 || amount > 1<<53-1 || strconv.FormatInt(amount, 10) != request.Amount {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "amount must be an integer string between 1 and 9007199254740991 micro-USDC")
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
	intent, err := h.dispatcher.Payment.CreateCommunityTopUpIn(tx, account.UserUUID, c.Param("id"), id, amount, request.RefundAddress, ctx)
	if err != nil {
		return communityFundingError(err)
	}
	response, err := paymentIntentResponse("USDC", intent)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return communityFundingError(err)
	}
	return c.JSON(http.StatusCreated, response)
}

func (h *Handler) checkCommunityFundingRequest(c echo.Context, req PaymentIntentRequest) error {
	if req.CommunityProjectID == "" {
		if req.CommunityExperimentID != "" || req.CommunityExperimentRevision != nil {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "an experiment association requires a community project")
		}
		return nil
	}
	if _, err := h.requireCommunityProject(c, req.CommunityProjectID); err != nil {
		return err
	}
	if (req.CommunityExperimentID == "") != (req.CommunityExperimentRevision == nil) ||
		(req.CommunityExperimentRevision != nil && *req.CommunityExperimentRevision <= 0) {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "experiment ID and positive revision must be supplied together")
	}
	return nil
}

func shareFundedMeasurement(ctx context.Context, db database.DBTX, account *caller, req PaymentIntentRequest, transactionID string) error {
	if err := pruneUnadmittedCommunityShares(ctx, db, req.CommunityProjectID); err != nil {
		return communityFailure(err)
	}
	var experiment any
	var revision any
	if req.CommunityExperimentID != "" {
		var kind string
		var bundle sql.NullString
		err := db.QueryRowContext(ctx, `SELECT r.kind,r.bundle FROM community_experiments e
			JOIN community_experiment_revisions r ON r.experiment_id=e.id
			WHERE e.id=? AND e.project_id=? AND r.revision=?`, req.CommunityExperimentID, req.CommunityProjectID, *req.CommunityExperimentRevision).Scan(&kind, &bundle)
		if errors.Is(err, sql.ErrNoRows) {
			return communityNotFound()
		}
		if err != nil {
			return communityFailure(err)
		}
		if bundle.Valid && !fundedProgramsMatch(kind, []byte(bundle.String), req.Debuglets) {
			return apiError(http.StatusBadRequest, CodeIntentMismatch, "submitted programs do not match the saved experiment revision")
		}
		experiment, revision = req.CommunityExperimentID, *req.CommunityExperimentRevision
	}
	result, err := db.ExecContext(ctx, `INSERT INTO community_measurements(project_id,measurement_id,shared_by,shared_at,experiment_id,experiment_revision)
		SELECT ?,?,id,unixepoch(),?,? FROM users WHERE uuid=?
		AND (SELECT count(*) FROM community_measurements WHERE project_id=?)<1024`,
		req.CommunityProjectID, transactionID, experiment, revision, account.UserUUID, req.CommunityProjectID)
	if err != nil {
		return communityFailure(err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return communityFailure(err)
	} else if n != 1 {
		return apiError(http.StatusConflict, CodeInvalidRequest, "project measurement history is full; remove an existing shared measurement first")
	}
	return nil
}

// An intent reserves a history slot before admission. Unused expired intents
// release that slot; admitted measurements retain their association.
func pruneUnadmittedCommunityShares(ctx context.Context, db database.DBTX, projectID string) error {
	// Release the reservation before its association, so an old intent cannot
	// subsequently admit work without a reserved place in the project history.
	if _, err := db.ExecContext(ctx, `UPDATE transactions SET status=?
		WHERE status=? AND expires_at<? AND id IN (
			SELECT transaction_id FROM community_funding WHERE project_id=?)
		AND NOT EXISTS(SELECT 1 FROM debuglets d WHERE d.transaction_id=transactions.id)
		AND NOT EXISTS(SELECT 1 FROM debuglet_order o WHERE o.transaction_id=transactions.id AND o.debuglet_id IS NOT NULL)`,
		models.Expired, models.Paid, models.NewUTCTime(time.Now()), projectID); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `DELETE FROM community_measurements
		WHERE project_id=? AND measurement_id IN (
			SELECT t.id FROM transactions t JOIN community_funding f ON f.transaction_id=t.id
			WHERE t.status IN (?,?))
		AND NOT EXISTS(SELECT 1 FROM debuglets d WHERE d.transaction_id=community_measurements.measurement_id)
		AND NOT EXISTS(SELECT 1 FROM debuglet_order o WHERE o.transaction_id=community_measurements.measurement_id AND o.debuglet_id IS NOT NULL)`,
		projectID, models.Expired, models.Refunded)
	return err
}

func fundedProgramsMatch(kind string, raw []byte, requests []DebugletRequest) bool {
	expected := map[string]int{}
	if kind == "workflow" {
		var bundle studio.Bundle
		if json.Unmarshal(raw, &bundle) != nil {
			return false
		}
		expected[bundle.WasmSHA256] = len(requests)
	} else {
		var bundle studio.ExperimentBundle
		if json.Unmarshal(raw, &bundle) != nil || len(bundle.Participants) != len(requests) {
			return false
		}
		for _, part := range bundle.Participants {
			if part.Bundle == nil {
				return false
			}
			expected[part.Bundle.WasmSHA256]++
		}
	}
	for _, req := range requests {
		wasm, err := base64.StdEncoding.DecodeString(req.Wasm)
		if err != nil {
			return false
		}
		digest := communityDocumentDigest(wasm)
		if expected[digest] == 0 {
			return false
		}
		expected[digest]--
	}
	return true
}
