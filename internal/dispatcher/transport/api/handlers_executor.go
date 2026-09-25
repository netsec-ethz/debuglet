// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// GET /executors
func (h *Handler) GetExecutors(c echo.Context) error {
	executors := h.dispatcher.ListExecutors()
	var resp []ExecutorResponse
	for _, e := range executors {
		resp = append(resp, ExecutorResponse{
			ID:                     e.ID,
			Ready:                  e.Ready,
			Version:                e.Version,
			LastSeen:               e.LastSeen.Unix(),
			TeslaDelaySec:          int64(e.TeslaDelay.Seconds()),
			TeslaAnchorTimestampNs: e.TeslaAnchorTimestamp.UnixNano(),
			TeslaAnchorKey:         e.TeslaAnchorKey,
			PricePerBw:             e.PricePerBwS,
			Currency:               e.Currency,
		})
	}
	return c.JSON(http.StatusOK, resp)
}

// GET /executors/by-ip?ip=<ip>[&n=<count>]
//
// Returns the executor ID of the executor whose source IP matches the query
// parameter, and the recent runs of the requesting account that were
// dispatched to it. Which executor serves an address is attribution data a
// measurement peer may need; which runs it carried is private, so the returned
// identifiers are the caller's own, never the run identifiers of another
// account. n defaults to 10 and can be raised by the caller up to
// maxRecentDebugletIDs, though the executor's ring retains at most 20 recent
// identifiers, so that is the real bound on the answer.
func (h *Handler) GetExecutorByIP(c echo.Context) error {
	established, err := requireCaller(c)
	if err != nil {
		return err
	}
	ip := c.QueryParam("ip")
	if ip == "" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "ip query parameter is required")
	}

	// Parse optional ?n= limit.
	n := 0
	if nStr := c.QueryParam("n"); nStr != "" {
		parsed, err := strconv.Atoi(nStr)
		if err != nil || parsed <= 0 {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "n must be a positive integer")
		}
		n = parsed
	}

	if n > maxRecentDebugletIDs {
		n = maxRecentDebugletIDs
	}

	exec, exists := h.dispatcher.GetExecutorByIPFull(ip)
	if !exists {
		return apiError(http.StatusNotFound, CodeNotFound, "no executor is registered for that IP")
	}

	candidates := exec.RecentDebugletIDs(n)
	owned, err := h.ownedDebugletIDs(c, established, candidates)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, ExecutorByIPResponse{
		ExecutorID:  exec.ID,
		DebugletIDs: owned,
	})
}

// maxRecentDebugletIDs bounds the candidate window this route inspects, so a
// caller-chosen n cannot turn one request into an unbounded ownership scan. The
// executor registry retains fewer identifiers than this, so it is a guard
// rather than the effective limit.
const maxRecentDebugletIDs = 100

// ownedDebugletIDs keeps the identifiers the caller may see, in the order the
// registry reported them. The local development bypass sees the registry's own
// window unchanged.
func (h *Handler) ownedDebugletIDs(c echo.Context, established *caller, candidates []uuid.UUID) ([]uuid.UUID, error) {
	if established.unrestricted() {
		return candidates, nil
	}
	// An empty result is an empty array: the contract documents a list, and a
	// caller that owns none of the candidates must not be told "null".
	owned := []uuid.UUID{}
	queries := database.New(h.db)
	for _, id := range candidates {
		owner, err := queries.GetDebugletOwnerUUID(c.Request().Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the run owner", err)
		}
		if owner == established.UserUUID {
			owned = append(owned, id)
		}
	}
	return owned, nil
}

// GET /executors/:id/tesla
//
// Returns the TESLA key schedule parameters for the given executor, including
// the public anchor key k_0 and the latest disclosed key k_τ. External
// verifiers use these to reconstruct chain keys and validate packet tags.
func (h *Handler) GetExecutorTesla(c echo.Context) error {
	id := c.Param("id")
	exec, exists := h.dispatcher.GetExecutor(id)
	if !exists {
		return apiError(http.StatusNotFound, CodeNotFound, "executor not found: "+echoed(id))
	}

	resp := ExecutorTeslaResponse{
		ExecutorID:        exec.ID,
		AnchorTimestampNs: exec.TeslaAnchorTimestamp.UnixNano(),
		DelaySec:          int64(exec.TeslaDelay.Seconds()),
	}
	if len(exec.TeslaAnchorKey) > 0 {
		resp.AnchorKey = base64.StdEncoding.EncodeToString(exec.TeslaAnchorKey)
	}

	// Attach the latest disclosed key if one exists.
	if epoch, key, ok := h.dispatcher.GetKeyStore().LatestDisclosed(id, exec.TeslaAnchorKey); ok {
		resp.DisclosedEpoch = epoch
		resp.DisclosedKey = base64.StdEncoding.EncodeToString(key)
	}

	return c.JSON(http.StatusOK, resp)
}
