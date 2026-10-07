// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	"github.com/netsec-ethz/debuglet/pkg/wire"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// GET /executors[?status=connected,disconnected,abandoned,never_connected]
func (h *Handler) GetExecutors(c echo.Context) error {
	statuses, err := executorStatuses(c.QueryParams()["status"])
	if err != nil {
		return err
	}
	offline := len(statuses) > 1 || statuses[0] != wire.ProbeConnected
	book, err := h.dispatcher.ProbeBook(c.Request().Context())
	if err != nil {
		if offline {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read executor status", err)
		}
		// The connected listing does not depend on the history: it then
		// reports each executor as connected since its registration.
		h.logger.Warn("Failed to read executor status history", zap.Error(err))
		book = h.dispatcher.LiveProbeBook()
	}
	executors := h.dispatcher.ListExecutors()
	// The maintenance switch is dispatcher-wide; read it once per listing.
	paused := dispatcher.AdmissionPaused() != nil
	caller := requestCaller(c)
	var resp []ExecutorResponse
	live := map[string]bool{}
	for _, e := range executors {
		live[e.ID] = true
		if !slices.Contains(statuses, wire.ProbeConnected) {
			continue
		}
		isdAS, listeners := e.Vantage()
		resp = append(resp, ExecutorResponse{
			Connectivity:           e.Connectivity(caller.Operator),
			CapabilityObservation:  e.CapabilityObservation(),
			AdmissionLimits:        &wire.ExecutorAdmissionLimits{Scheduling: true, MinTimeoutMS: 1, MaxTimeoutMS: models.MaxPolicyTimeoutMS, MaxBandwidthBPS: models.MaxPolicyBandwidthBPS, PriceUnit: "currency_per_bps_second"},
			Admission:              e.Admission(paused),
			Display:                e.Display(),
			SCIONISDAS:             isdAS,
			Listeners:              listeners,
			Clock:                  e.Clock(),
			IPMetadata:             e.IPMetadata(),
			ProbeAddressing:        e.Addressing(caller.Operator),
			ProbeStatus:            book.Live(&e),
			ID:                     e.ID,
			Capabilities:           e.Capabilities,
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
	if offline {
		resp = append(resp, book.Offline(live, statuses, h.dispatcher.ConfiguredDisplay, caller.Operator)...)
	}
	return c.JSON(http.StatusOK, resp)
}

// executorStatuses reads the status filter: comma-separated or repeated status
// names. Without one the listing keeps its original meaning, the connected
// executors only.
func executorStatuses(values []string) ([]string, error) {
	out := []string{}
	for _, value := range values {
		for _, name := range strings.Split(value, ",") {
			if !slices.Contains(wire.ProbeStatuses, name) {
				return nil, apiError(http.StatusBadRequest, CodeInvalidRequest, "status must be a comma-separated list of "+strings.Join(wire.ProbeStatuses, ", "))
			}
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, wire.ProbeConnected)
	}
	return out, nil
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

	epochSeconds := int64(exec.TeslaDelay.Seconds())
	resp := ExecutorTeslaResponse{
		ExecutorID:             exec.ID,
		AnchorTimestampNs:      exec.TeslaAnchorTimestamp.UnixNano(),
		DelaySec:               epochSeconds,
		EpochSeconds:           epochSeconds,
		DisclosureDelayEpochs:  exec.TeslaDisclosureDelay,
		DisclosureDelaySeconds: exec.TeslaDisclosureDelay * epochSeconds,
	}
	if len(exec.TeslaAnchorKey) > 0 {
		resp.AnchorKey = base64.StdEncoding.EncodeToString(exec.TeslaAnchorKey)
	}

	// Attach the latest disclosed key if one exists.
	if epoch, key, ok := h.dispatcher.GetKeyStore().LatestDisclosed(id, exec.TeslaAnchorKey); ok {
		resp.DisclosedEpoch = epoch
		resp.DisclosedKey = base64.StdEncoding.EncodeToString(key)
	}
	resp.NextDisclosureEpoch = resp.DisclosedEpoch + 1
	chain := tag.Chain{Start: exec.TeslaAnchorTimestamp, Interval: exec.TeslaDelay, DisclosureDelay: exec.TeslaDisclosureDelay}
	if at, ok := chain.DisclosableAt(resp.NextDisclosureEpoch); ok {
		resp.NextDisclosureAtNs = at.UnixNano()
	}

	return c.JSON(http.StatusOK, resp)
}
