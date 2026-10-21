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
	"github.com/netsec-ethz/debuglet/internal/dispatcher/measurementsource"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

const maxMeasurementSourceBytes = 4 << 20

// PostMeasurementSource records the owner's source association after admission.
// Matching program digests identify the submitted modules, not compiler proof.
func (h *Handler) PostMeasurementSource(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	var input measurementsource.Input
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxMeasurementSourceBytes)
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return err
	}
	source, created, err := (measurementsource.Store{DB: h.db}).Save(c.Request().Context(), account.UserUUID, c.Param("id"), input)
	if err != nil {
		return measurementSourceError(err)
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return c.JSON(status, source)
}

func (h *Handler) GetRunSource(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	id, err := parseDebugletID(c.Param("id"))
	if err != nil {
		return err
	}
	tx, err := h.db.BeginTx(c.Request().Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return libraryFailure(err)
	}
	defer tx.Rollback()
	source, err := getRunSource(c.Request().Context(), tx, id, account.UserUUID)
	if errors.Is(err, sql.ErrNoRows) {
		return apiError(http.StatusNotFound, CodeNotFound, "original builder source is unavailable for this run")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, source)
}

// Result highlights read their source inside the same transaction as the
// highlight, so membership and retention cannot change between those reads.
func getRunSource(ctx context.Context, tx *sql.Tx, runID, callerID uuid.UUID) (*wire.SourceDocument, error) {
	source, err := measurementsource.Read(ctx, tx, runID, callerID)
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		return source, err
	}
	return nil, measurementSourceError(err)
}

func measurementSourceError(err error) error {
	var validation *measurementsource.ValidationError
	var retention *measurementsource.RetentionError
	switch {
	case errors.As(err, &validation):
		if validation.Conflict {
			return communityConflict(validation.Message)
		}
		return apiError(http.StatusBadRequest, CodeInvalidRequest, validation.Message)
	case errors.Is(err, measurementsource.ErrNotFound):
		return debugletNotFound()
	case errors.Is(err, measurementsource.ErrPayloadDeleted):
		return apiError(http.StatusGone, CodePayloadDeleted, err.Error())
	case errors.As(err, &retention):
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, retention.Error(), retention.Cause)
	default:
		return libraryFailure(err)
	}
}
