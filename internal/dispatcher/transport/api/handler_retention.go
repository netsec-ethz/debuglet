// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
)

const (
	CodePayloadDeleted      = "payload_deleted"
	CodePayloadNotDeletable = "payload_not_deletable"
)

func (h *Handler) requireRetainedPayload(ctx context.Context, id uuid.UUID) error {
	return requireRetainedPayload(ctx, database.New(h.db), id)
}

func requireRetainedPayload(ctx context.Context, q *database.Queries, id uuid.UUID) error {
	_, err := q.GetPayloadTombstone(ctx, id)
	if err == nil {
		return apiError(http.StatusGone, CodePayloadDeleted, "measurement payload was deleted; run identity and outcome remain available")
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to inspect payload retention", err)
}

// DeleteDebugletPayload is deliberately distinct from DELETE /debuglet, which
// requests cancellation. Operator read privileges do not grant deletion of
// another account's payload. The explicit local profile owns ownerless runs.
func (h *Handler) DeleteDebugletPayload(c echo.Context) error {
	established, err := requireCaller(c)
	if err != nil {
		return err
	}
	id, err := parseDebugletID(c.Param("id"))
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	q := database.New(h.db)
	if _, err := q.GetDebugletByUUID(ctx, id); errors.Is(err, sql.ErrNoRows) {
		return debugletNotFound()
	} else if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to query debuglet", err)
	}
	owner, err := q.GetDebugletOwnerUUID(ctx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to query debuglet owner", err)
	}
	callerOwner, authenticatedOwner := established.owner()
	if !(err == nil && authenticatedOwner && owner == callerOwner) && !(errors.Is(err, sql.ErrNoRows) && established.Local) {
		return debugletNotFound()
	}
	if err := h.dispatcher.DeleteCompletedPayload(ctx, id, false); err != nil {
		if errors.Is(err, dispatcher.ErrPayloadNotDeletable) {
			return apiErrorFrom(http.StatusConflict, CodePayloadNotDeletable, "payload requires completed output and confirmed executor retirement", err)
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to delete measurement payload", err)
	}
	return c.NoContent(http.StatusNoContent)
}
