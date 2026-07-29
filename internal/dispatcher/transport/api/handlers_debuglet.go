package api

import (
	"debuglet/internal/dispatcher"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

// PUT /debuglet
func (h *Handler) SubmitDebuglets(c echo.Context) error {
	var req SubmitDebugletsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}

	var reqs = req.Debuglets
	if len(reqs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no debuglets provided")
	}

	price := int64(0)
	for _, req := range reqs {
		executor, exists := h.dispatcher.GetExecutor(req.ExecutorID)
		if !exists {
			continue
		}
		//TODO guard against overflow
		price += int64(executor.PricePerBw) * req.Policy.FloorBW * req.Policy.TimeoutMS
	}

	transactionId, intent, err := h.dispatcher.Payment.CreatePaymentIntent(price, req.PaymentMethod)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "faield to create payment intent: "+err.Error())
	}

	var specs []dispatcher.DebugletSpec
	for i, req := range reqs {
		spec, err := APIToSpec(req)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid request (i=%d): %v", i, err))
		}
		spec.TransactionID = transactionId
		specs = append(specs, spec)
	}

	if IDs, err := h.dispatcher.SubmitDebuglets(c.Request().Context(), specs); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initialize debuglets: "+err.Error())
	} else {
		return c.JSON(http.StatusOK, SubmitDebugletsResponse{IDs, intent})
	}
}

// GET /debuglet/:id
// Uses Server-Sent Events (SSE) to stream state changes and output
func (h *Handler) GetLogsSSE(c echo.Context) error {
	debugletID := c.Param("id")

	w := c.Response()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	store, err := h.dispatcher.GetStore(debugletID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid debuglet: "+err.Error())
	}

	sseID := 0
	sendEvent := func(eventType string, data []byte) error {
		event := SSEEvent{
			ID:    fmt.Appendf([]byte{}, "%d", sseID),
			Data:  data,
			Event: []byte(eventType),
		}
		sseID++
		if err := event.MarshalTo(w); err != nil {
			return err
		}
		return http.NewResponseController(w).Flush()
	}

	if store.State == dispatcher.RunStateExited {
		if err := sendEvent("state", []byte(store.State.String())); err != nil {
			return err
		}
		if len(store.Logs) > 0 {
			if err := sendEvent("output", store.Logs); err != nil {
				return err
			}
		}
		return nil
	}

	outputCh := make(chan []byte, 1)
	stateCh := make(chan dispatcher.DebugletRunState, 1)

	seqID, done, err := h.dispatcher.RegisterLogConnection(debugletID, outputCh, stateCh)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid debuglet: "+err.Error())
	}
	defer h.dispatcher.RemoveLogConnection(debugletID, seqID)

	if err := sendEvent("state", []byte(store.State.String())); err != nil {
		return err
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.Request().Context().Done():
			return nil
		case <-done:
			return nil
		case output := <-outputCh:
			if err := sendEvent("output", output); err != nil {
				return err
			}
		case state := <-stateCh:
			if err := sendEvent("state", []byte(state.String())); err != nil {
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

// GET /debuglet/:id/state
func (h *Handler) GetDebugletState(c echo.Context) error {
	debugletID := c.Param("id")
	store, err := h.dispatcher.GetStore(debugletID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid debuglet: "+err.Error())
	}
	return c.JSON(http.StatusOK, DebugletStateResponse{
		State:      store.State.String(),
		Logs:       base64.StdEncoding.EncodeToString(store.Logs),
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
