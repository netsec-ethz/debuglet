// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

// GetDebugletRecovery returns an observation without changing the stored run.
func (h *Handler) GetDebugletRecovery(c echo.Context) error {
	id, err := parseDebugletID(c.Param("id"))
	if err != nil {
		return err
	}
	if err := h.authorizeDebuglet(c, id); err != nil {
		return err
	}
	document, err := h.dispatcher.Recovery(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return debugletNotFound()
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to inspect debuglet recovery", err)
	}
	return c.JSON(http.StatusOK, document)
}
