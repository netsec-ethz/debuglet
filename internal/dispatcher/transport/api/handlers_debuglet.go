package api

import (
	"debuglet/internal/dispatcher/database"
	"debuglet/internal/dispatcher/models"
	"debuglet/internal/dispatcher/resource"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// PUT /debuglet
func (h *Handler) PutDebuglets(c echo.Context) error {
	var req SubmitDebugletsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}

	var reqs = req.Debuglets
	if len(reqs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no debuglets provided")
	}
	transactionId := req.TransactionId
	tx, err := h.dispatcher.Payment.GetTransaction(c.Request().Context(), transactionId)
	h.logger.Info("transaction_id", zap.String("id", tx.ID), zap.Int64("status", tx.Status))
	if err != nil || tx.AuthKey != req.AuthKey {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid auth key")
	}
	if !strings.EqualFold(tx.Hash, hashDebugletRequest(req.Debuglets)) {
		h.logger.Info("mismatched request", zap.String("expected", tx.Hash), zap.String("found", hashDebugletRequest(req.Debuglets)))
		return echo.NewHTTPError(http.StatusBadRequest, "Request does not match the intent")
	}
	if tx.Status != int64(models.Paid) {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Transaction %s has not yed been compeleted", req.TransactionId))
	}

	var specs []models.DebugletSpec
	for i, req := range reqs {
		spec, err := APIToSpec(req)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid request (i=%d): %v", i, err))
		}
		spec.TransactionID = transactionId
		specs = append(specs, spec)
	}

	if IDs, err := h.dispatcher.SubmitDebuglets(c.Request().Context(), specs); err != nil {
		if errors.Is(err, resource.ErrCapacityFull) {
			return echo.NewHTTPError(http.StatusConflict, "capacity exceeded: "+err.Error())
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initialize debuglets: "+err.Error())
	} else {
		return c.JSON(http.StatusOK, IDs)
	}
}

// GET /debuglet/:id/logs
func (h *Handler) GetDebugletLogs(c echo.Context) error {
	debugletID := c.Param("id")

	after, err := strconv.ParseInt(c.QueryParam("after"), 10, 64)
	if err != nil {
		after = 0
	}
	limit, err := strconv.ParseInt(c.QueryParam("limit"), 10, 64)
	if err != nil || limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	ctx := c.Request().Context()
	queries := database.New(h.dispatcher.DB())

	dbLogs, err := queries.ListDebugletLogs(ctx, database.ListDebugletLogsParams{
		DebugletID: debugletID,
		ID:         after,
		Limit:      limit,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to query logs: "+err.Error())
	}

	store, err := h.dispatcher.GetStore(debugletID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid debuglet: "+err.Error())
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
		State:   store.State.String(),
		Error:   store.Err,
		After:   lastID,
		Logs:    entries,
		HasMore: int64(len(dbLogs)) == limit,
	})
}

// GET /debuglet/:id/state
func (h *Handler) GetDebugletState(c echo.Context) error {
	debugletID := c.Param("id")
	store, err := h.dispatcher.GetStore(debugletID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid debuglet: "+err.Error())
	}
	return c.JSON(http.StatusOK, DebugletStateResponse{
		State:      store.State.String(),
		Error:      store.Err,
		ExecutorID: store.ExecutorID,
	})
}

// DELETE /debuglet
func (h *Handler) DeleteDebuglet(c echo.Context) error {
	var req DebugletDeleteRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}

	if err := h.dispatcher.AbortDebuglet(c.Request().Context(), req.ExecutorID, req.DebugletID, "cancelled via API"); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	return c.NoContent(http.StatusNoContent)
}
