// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
)

// authorizeDebugletRead admits an owner or a current member of a community
// where the measurement was shared. Its result reports owner-only management
// authority; sharing never grants cancellation, deletion or payment access.
func (h *Handler) authorizeDebugletRead(c echo.Context, id uuid.UUID) (bool, error) {
	established, err := requireCaller(c)
	if err != nil {
		return false, err
	}
	if established.unrestricted() {
		return true, nil
	}
	q := database.New(h.db)
	ctx := c.Request().Context()
	owner, err := q.GetDebugletOwnerUUID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, debugletNotFound()
	}
	if err != nil {
		return false, apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the run owner", err)
	}
	if owner == established.UserUUID {
		return !established.API || credentialAllows(established.Scopes, http.MethodDelete, "/debuglet"), nil
	}
	allowed, err := q.CanReadCommunityDebuglet(ctx, database.CanReadCommunityDebugletParams{
		RunUuid: id, UserUuid: established.UserUUID,
	})
	if err != nil {
		return false, apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read measurement access", err)
	}
	if !allowed {
		return false, debugletNotFound()
	}
	return false, nil
}
