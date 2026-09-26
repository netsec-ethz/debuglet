// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/ids"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PUT /debuglet
func (h *Handler) PutDebuglets(c echo.Context) error {
	// A submission acts on the caller's own payment order, so the caller is
	// established before the body is read: an unauthenticated request costs no
	// megabytes of parsing. Ownership of the transaction is decided next; the
	// auth key authorizes one batch, it does not identify who may spend the
	// order.
	established, err := requireCaller(c)
	if err != nil {
		return err
	}

	var req SubmitDebugletsRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}

	var reqs = req.Debuglets
	if len(reqs) == 0 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "no debuglets provided")
	}
	// Maintenance is checked before anything is admitted, scheduled or
	// inserted: a dispatcher that will not accept work must not consume a
	// payment intent first. The refusal accounts for an order that was
	// already paid before admission stopped, so a submitter is never left
	// with neither the work nor the money.
	if err := dispatcher.AdmissionPaused(); err != nil {
		return h.refuseForMaintenance(c, established, req, err)
	}
	transactionId := req.TransactionId
	tx, err := h.dispatcher.Payment.GetTransaction(c.Request().Context(), transactionId)
	h.logger.Info("transaction_id", zap.String("id", tx.ID), zap.Int64("status", tx.Status))
	if err != nil || tx.AuthKey != req.AuthKey {
		return apiErrorFrom(http.StatusUnauthorized, CodeUnauthorized, "unknown transaction or wrong auth key", err)
	}
	// Another account's transaction, and one recorded before orders had an
	// owner, are refused exactly like an unknown one.
	if err := h.authorizeTransactionOwner(c, established, transactionId,
		apiError(http.StatusUnauthorized, CodeUnauthorized, "unknown transaction or wrong auth key")); err != nil {
		return err
	}
	if !strings.EqualFold(tx.Hash, hashDebugletRequest(req.Debuglets)) {
		h.logger.Info("mismatched request", zap.String("expected", tx.Hash), zap.String("found", hashDebugletRequest(req.Debuglets)))
		return apiError(http.StatusBadRequest, CodeIntentMismatch, "Request does not match the intent")
	}
	// A refunded order is spent: the money went back, so the batch it paid
	// for is not admitted again however often it is submitted.
	if tx.Status == int64(models.Refunded) {
		return apiError(http.StatusBadRequest, CodePaymentIncomplete,
			fmt.Sprintf("Transaction %s was refunded and cannot be spent again", echoed(req.TransactionId)))
	}
	if tx.Status != int64(models.Paid) {
		return apiError(http.StatusBadRequest, CodePaymentIncomplete,
			fmt.Sprintf("Transaction %s has not yet been completed", echoed(req.TransactionId)))
	}
	// Payment-mode preflight on the persisted method: a paid chain transaction
	// (stored Method "SUI", currency USDC or SUI) is rejected with 503 while
	// blockchain payments are disabled, before any scheduler admission, debuglet
	// insert or refund attempt. TEST transactions pass in both modes.
	if err := h.dispatcher.Payment.CheckPaymentMethod(tx.Method); err != nil {
		if errors.Is(err, payments.ErrPaymentsDisabled) {
			return apiError(http.StatusServiceUnavailable, CodePaymentsDisabled, paymentsDisabledMessage)
		}
		return apiErrorFrom(http.StatusBadRequest, CodeUnsupportedPaymentMethod,
			"unsupported payment method: "+echoed(tx.Method), err)
	}

	var specs []models.DebugletSpec
	for i, req := range reqs {
		if err := validatePolicy(req.OrderID, req.Policy); err != nil {
			return err
		}
		spec, err := APIToSpec(req)
		if err != nil {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, fmt.Sprintf("invalid request (i=%d): %v", i, err))
		}
		spec.TransactionID = transactionId
		spec.OrderID = req.OrderID
		specs = append(specs, spec)
	}

	var userID *uuid.UUID
	if owner, ok := established.owner(); ok {
		userID = &owner
	}

	if IDs, err := h.dispatcher.SubmitDebuglets(c.Request().Context(), specs, userID); err != nil {
		// A refusal over orders that already carry runs keeps the payment:
		// those runs may be executing or credited, and refunding would pay
		// for the same work twice.
		if !errors.Is(err, dispatcher.ErrPaymentInUse) {
			if err2 := h.dispatcher.Payment.RefundTransaction(transactionId, c.Request().Context()); err2 != nil {
				h.logger.Warn("Failed to refund transaction", zap.String("ID", transactionId), zap.Error(err2))
			}
		}
		if errors.Is(err, dispatcher.ErrMaintenanceMode) {
			return apiErrorFrom(http.StatusServiceUnavailable, CodeUnavailable, err.Error(), err)
		}
		if errors.Is(err, resource.ErrCapacityFull) {
			return apiErrorFrom(http.StatusConflict, CodeCapacityExhausted, "capacity exceeded", err)
		}
		// A policy admission refuses on its numbers is a rejected request, not
		// a failure of the server. Its message names the field and carries no
		// caller-supplied text, so it is reported as it is.
		if errors.Is(err, dispatcher.ErrInvalidPolicy) {
			return apiErrorFrom(http.StatusBadRequest, CodeInvalidPolicy, err.Error(), err)
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to initialize debuglets", err)
	} else {
		return c.JSON(http.StatusOK, IDs)
	}
}

// refuseForMaintenance answers a submission a dispatcher in maintenance will
// not admit. Nothing is admitted, scheduled or inserted whatever this finds;
// what it decides is what happens to a payment order that was already paid
// when admission stopped. Such an order is refunded here, because the batch it
// paid for is not being accepted, and a refunded order is spent: the same
// batch is refused on the transaction's status from then on. A refund that
// cannot be performed is not silently dropped either: the refusal then says
// the order is still paid, so the same batch can be submitted again once
// admission resumes.
//
// The order is read only to answer that question, and only an order the caller
// has proved it may spend is reported on at all. An unknown transaction,
// another account's, and a wrong auth key are answered with the bare refusal,
// so nothing here tells a caller about an order it could not already read.
func (h *Handler) refuseForMaintenance(c echo.Context, established *caller, req SubmitDebugletsRequest, cause error) error {
	message := cause.Error()
	ctx := c.Request().Context()
	tx, err := h.dispatcher.Payment.GetTransaction(ctx, req.TransactionId)
	spendable := err == nil && tx.AuthKey == req.AuthKey &&
		h.authorizeTransactionOwner(c, established, req.TransactionId,
			apiError(http.StatusUnauthorized, CodeUnauthorized, "unknown transaction or wrong auth key")) == nil
	switch {
	case !spendable:
	case tx.Status == int64(models.Refunded):
		message += "; this payment order was refunded and cannot be spent again"
	case tx.Status == int64(models.Paid):
		if refundErr := h.dispatcher.Payment.RefundTransaction(req.TransactionId, ctx); refundErr != nil {
			h.logger.Warn("Failed to refund transaction", zap.String("ID", req.TransactionId), zap.Error(refundErr))
			message += "; this payment order is paid and was not refunded, so it stays paid and the same batch can be submitted again once admission resumes"
		} else {
			message += "; this payment order was paid and has been refunded, so it cannot be spent again"
		}
	}
	return apiError(http.StatusServiceUnavailable, CodeUnavailable, message)
}

// GET /debuglet/:id/logs
func (h *Handler) GetDebugletLogs(c echo.Context) error {
	debugletID := c.Param("id")

	after := int64(0)
	if _, present := c.QueryParams()["after"]; present {
		parsed, err := strconv.ParseInt(c.QueryParam("after"), 10, 64)
		if err != nil || parsed < 0 {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid after parameter: must be a non-negative integer")
		}
		after = parsed
	}
	limit := int64(100)
	if _, present := c.QueryParams()["limit"]; present {
		parsed, err := strconv.ParseInt(c.QueryParam("limit"), 10, 64)
		if err != nil || parsed <= 0 {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid limit parameter: must be a positive integer")
		}
		limit = parsed
	}
	if limit > 1000 {
		limit = 1000
	}

	id, err := parseDebugletID(debugletID)
	if err != nil {
		return err
	}
	if err := h.authorizeDebuglet(c, id); err != nil {
		return err
	}

	ctx := c.Request().Context()
	queries := database.New(h.db)

	dbLogs, err := queries.ListDebugletLogs(ctx, database.ListDebugletLogsParams{
		Uuid:  id,
		After: after,
		Limit: limit,
	})
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to query logs", err)
	}

	deb, err := queries.GetDebugletByUUID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apiError(http.StatusNotFound, CodeNotFound, "debuglet not found")
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to query debuglet", err)
	}

	var entries []DebugletLogEntry
	lastID := after
	for _, l := range dbLogs {
		entries = append(entries, DebugletLogEntry{
			ID:        l.ID,
			Timestamp: l.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Output:    base64.StdEncoding.EncodeToString(l.Output),
		})
		lastID = l.ID
	}

	return c.JSON(http.StatusOK, DebugletLogsResponse{
		State:   deb.State.String(),
		Error:   deb.Error.String,
		After:   lastID,
		Logs:    entries,
		HasMore: int64(len(dbLogs)) == limit,
	})
}

// parseDebugletID accepts the run IDs the control protocol accepts: the
// lowercase canonical spelling of a non-nil UUID.
func parseDebugletID(value string) (uuid.UUID, error) {
	id, ok := ids.ParseCanonical(value)
	if !ok {
		return uuid.Nil, apiError(http.StatusBadRequest, CodeInvalidRequest,
			"invalid debuglet id: want a lowercase canonical, non-nil UUID")
	}
	return id, nil
}

// GET /debuglet/:id/state
func (h *Handler) GetDebugletState(c echo.Context) error {
	debugletID := c.Param("id")

	id, err := parseDebugletID(debugletID)
	if err != nil {
		return err
	}
	if err := h.authorizeDebuglet(c, id); err != nil {
		return err
	}

	queries := database.New(h.db)
	deb, err := queries.GetDebugletByUUID(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apiError(http.StatusNotFound, CodeNotFound, "debuglet not found")
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to query debuglet", err)
	}

	return c.JSON(http.StatusOK, DebugletStateResponse{
		State:      deb.State.String(),
		Error:      deb.Error.String,
		ExecutorID: deb.ExecutorID,
	})
}

// DELETE /debuglet
func (h *Handler) DeleteDebuglet(c echo.Context) error {
	var req DebugletDeleteRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}

	// Ownership is decided before the cancellation is attempted, so a run the
	// caller may not see is neither cancelled nor reported as existing. The
	// acknowledgement semantics of a permitted cancellation are unchanged.
	if err := h.authorizeDebuglet(c, req.DebugletID); err != nil {
		return err
	}

	if err := h.dispatcher.AbortDebuglet(c.Request().Context(), req.ExecutorID, req.DebugletID, "cancelled via API"); err != nil {
		// The executor acknowledged the cancellation, but its result was not
		// recorded and the run's state does not show it. That is neither a
		// refusal nor the 204 acknowledgement; the cause stays in the log.
		if errors.Is(err, dispatcher.ErrCancellationNotRecorded) {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "cancellation acknowledged but its result was not recorded", err)
		}
		// The executor answered with a refusal, whatever its code: nothing
		// was cancelled.
		if errors.Is(err, dispatcher.ErrAbortRefused) {
			return apiErrorFrom(http.StatusBadRequest, CodeCancelRefused, "cancellation refused", err)
		}
		switch status.Code(err) {
		case codes.Internal:
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to process cancellation", err)
		// The Abort may or may not have reached the executor, so the
		// cancellation is neither refused nor confirmed.
		case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "cancellation not confirmed", err)
		}
		// The dispatcher's own diagnostic carries transport and session
		// internals; the caller learns that the cancellation was refused.
		return apiErrorFrom(http.StatusBadRequest, CodeCancelRefused, "cancellation refused", err)
	}
	return c.NoContent(http.StatusNoContent)
}

// GET /list-debuglets
func (h *Handler) ListUserDebuglets(c echo.Context) error {
	established, err := requireAccount(c)
	if err != nil {
		return err
	}

	limitStr := c.QueryParam("limit")
	var limit int64 = 100
	if strings.TrimSpace(limitStr) != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil || l <= 0 {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid limit parameter")
		}
		limit = min(int64(l), 100)
	}

	offsetStr := c.QueryParam("offset")
	var offset int64 = 0
	if strings.TrimSpace(offsetStr) != "" {
		o, err := strconv.Atoi(offsetStr)
		if err != nil || o < 0 {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid offset parameter")
		}
		offset = int64(o)
	}

	queries := database.New(h.db)
	debuglets, err := queries.ListDebugletsByUserUUID(c.Request().Context(), database.ListDebugletsByUserUUIDParams{
		Uuid:   established.UserUUID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to retrieve debuglets for user", err)
	}

	resp := make([]DebugletResponse, len(debuglets))
	for i, d := range debuglets {
		resp[i] = DebugletResponse{
			ID:         d.Uuid,
			StartTime:  d.StartTime.Unix(),
			EndTime:    d.EndTime.Unix(),
			Usage:      d.Usage,
			ExecutorID: d.ExecutorID,
			Addresses:  d.Addresses,
			State:      d.State.String(),
		}
	}

	return c.JSON(http.StatusOK, resp)
}
