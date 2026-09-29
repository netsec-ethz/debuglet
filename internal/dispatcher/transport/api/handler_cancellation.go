// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

// GetDebugletCancellation inspects an existing request without sending an Abort.
func (h *Handler) GetDebugletCancellation(c echo.Context) error {
	id, err := parseDebugletID(c.Param("id"))
	if err != nil {
		return err
	}
	if err := h.authorizeDebuglet(c, id); err != nil {
		return err
	}
	document, err := h.dispatcher.Cancellation(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return debugletNotFound()
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to inspect cancellation", err)
	}
	return c.JSON(http.StatusOK, document)
}
