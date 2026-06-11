package api

import (
	"debuglet/internal/dispatcher"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

// PUT /debuglet
func (h *Handler) SubmitDebuglets(c echo.Context) error {
	var reqs []DebugletRequest
	if err := c.Bind(&reqs); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}
	if len(reqs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no debuglets provided")
	}

	var specs []dispatcher.DebugletSpec
	for i, req := range reqs {
		spec, err := APIToSpec(req)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid request (i=%d): %v", i, err))
		}
		specs = append(specs, spec)
	}

	if IDs, err := h.dispatcher.SubmitDebuglets(c.Request().Context(), specs); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initialize debuglets: "+err.Error())
	} else {
		return c.JSON(http.StatusOK, IDs)
	}
}

// GET /debuglet/:id
// Uses Server-Sent Events (SSE) to stream logs/results
func (h *Handler) GetLogsWS(c echo.Context) error {
	debugletID := c.Param("id")

	w := c.Response()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	outputCh := make(chan []byte, 1)
	seqID, done, err := h.dispatcher.RegisterLogConnection(debugletID, outputCh)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid debuglet: "+err.Error())
	}
	defer h.dispatcher.RemoveLogConnection(debugletID, seqID)

	sseID := 0
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.Request().Context().Done():
			return nil
		case <-done:
			return nil
		case output := <-outputCh:
			event := SSEEvent{
				ID:    fmt.Appendf([]byte{}, "%d", sseID),
				Data:  output,
				Event: []byte("output"),
			}
			sseID++
			if err := event.MarshalTo(w); err != nil {
				return err
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return err
			}
		case <-ticker.C:
			event := SSEEvent{Comment: []byte("keepalive")}
			if err := event.MarshalTo(w); err != nil {
				return err
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return err
			}
		}
	}
}

// DELETE /debuglet
func (h *Handler) AbortDebuglet(c echo.Context) error {
	var req DebugletDeleteRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}

	if err := h.dispatcher.AbortDebuglet(c.Request().Context(), req.ExecutorID, req.DebugletID, "cancelled via API"); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	return c.NoContent(http.StatusNoContent)
}
