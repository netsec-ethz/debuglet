package api

import (
	"encoding/base64"
	"net/http"
	"strconv"

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
			PricePerBw:             e.PricePerBw,
		})
	}
	return c.JSON(http.StatusOK, resp)
}

// GET /executors/by-ip?ip=<ip>[&n=<count>]
//
// Returns the executor ID and the last n debuglet IDs dispatched to the
// executor whose source IP matches the query parameter. n defaults to 10 and
// can be overridden by the caller.
func (h *Handler) GetExecutorByIP(c echo.Context) error {
	ip := c.QueryParam("ip")
	if ip == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ip query parameter is required")
	}

	// Parse optional ?n= limit.
	n := 0
	if nStr := c.QueryParam("n"); nStr != "" {
		parsed, err := strconv.Atoi(nStr)
		if err != nil || parsed <= 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "n must be a positive integer")
		}
		n = parsed
	}

	exec, exists := h.dispatcher.GetExecutorByIPFull(ip)
	if !exists {
		return echo.NewHTTPError(http.StatusNotFound, "no executor found for IP "+ip)
	}

	return c.JSON(http.StatusOK, ExecutorByIPResponse{
		ExecutorID:  exec.ID,
		DebugletIDs: exec.RecentDebugletIDs(n),
	})
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
		return echo.NewHTTPError(http.StatusNotFound, "executor not found: "+id)
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
	if epoch, key, ok := h.dispatcher.GetKeyStore().LatestDisclosed(id); ok {
		resp.DisclosedEpoch = epoch
		resp.DisclosedKey = base64.StdEncoding.EncodeToString(key)
	}

	return c.JSON(http.StatusOK, resp)
}
