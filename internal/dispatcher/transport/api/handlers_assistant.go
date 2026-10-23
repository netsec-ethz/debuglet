// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/studio"
	"golang.org/x/time/rate"
)

type assistantState struct {
	client   *studio.Assistant
	slots    studioProxy
	requests *rate.Limiter
}

// Assistant is independent of compiler availability. Its provider connection
// receives source explicitly sent by the caller, never account credentials.
func Assistant(client *studio.Assistant) Option {
	return func(h *Handler) {
		h.assistant = assistantState{client: client, slots: studioProxy{active: make(map[uuid.UUID]bool)}, requests: rate.NewLimiter(rate.Every(10*time.Second), 4)}
	}
}

func (h *Handler) registerAssistantRoutes(e *echo.Echo) {
	e.GET("/studio/assistant", h.assistantAvailability)
	e.POST("/studio/assistant", h.assistantReply)
}

func assistantRoute(c echo.Context) error {
	if c.Request().URL.EscapedPath() != c.Path() || c.Request().URL.RawQuery != "" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "assistant routes do not accept encoded paths or query parameters")
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return nil
}

func (h *Handler) assistantAvailability(c echo.Context) error {
	if _, err := requireAccount(c); err != nil {
		return err
	}
	if err := assistantRoute(c); err != nil {
		return err
	}
	result := struct {
		Enabled bool   `json:"enabled"`
		Model   string `json:"model,omitempty"`
	}{Enabled: h.assistant.client != nil}
	if h.assistant.client != nil {
		result.Model = h.assistant.client.Model()
	}
	return c.JSON(http.StatusOK, result)
}

func (h *Handler) assistantReply(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if err := assistantRoute(c); err != nil {
		return err
	}
	if h.assistant.client == nil {
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, "experiment assistance is not enabled on this dispatcher")
	}
	if err := h.allowAdmissionRequest(c, account); err != nil {
		return err
	}
	if !h.assistant.slots.acquire(account.UserUUID) {
		c.Response().Header().Set("Retry-After", "1")
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "experiment assistant is busy; retry shortly")
	}
	defer h.assistant.slots.release(account.UserUUID)
	req := c.Request()
	content, _, err := mime.ParseMediaType(req.Header.Get(echo.HeaderContentType))
	if err != nil || content != echo.MIMEApplicationJSON || req.Header.Get("Content-Encoding") != "" {
		return apiError(http.StatusUnsupportedMediaType, CodeUnsupportedMediaType, "assistant request body must be uncompressed application/json")
	}
	if req.ContentLength > studio.AssistantRequestLimit {
		return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "assistant request body exceeds its size limit")
	}
	controller := http.NewResponseController(c.Response().Writer)
	_ = controller.SetReadDeadline(time.Now().Add(30 * time.Second))
	input, err := studio.DecodeAssistantRequest(http.MaxBytesReader(c.Response().Writer, req.Body, studio.AssistantRequestLimit))
	_ = controller.SetReadDeadline(time.Time{})
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "assistant request body exceeds its size limit")
		}
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "assistant request is invalid: use workflow or experiment JSON up to 256 KiB, a non-empty prompt up to 8192 bytes, and at most 12 user/assistant history messages up to 16384 bytes in total")
	}
	if !h.assistant.requests.Allow() {
		c.Response().Header().Set("Retry-After", "10")
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "experiment assistant request limit reached; retry shortly")
	}
	ctx, cancel := context.WithTimeout(req.Context(), studio.AssistantTimeout)
	defer cancel()
	result, err := h.assistant.client.Reply(ctx, input)
	if err != nil {
		if errors.Is(err, studio.ErrAssistantTimeout) || ctx.Err() != nil {
			return apiError(http.StatusGatewayTimeout, CodeUnavailable, "experiment assistant timed out or was canceled; your draft is unchanged")
		}
		if errors.Is(err, studio.ErrAssistantInvalidReply) {
			return apiError(http.StatusUnprocessableEntity, CodeInvalidRequest, "experiment assistant could not produce a valid experiment; your draft is unchanged")
		}
		return apiError(http.StatusBadGateway, CodeUnavailable, "experiment assistant provider is unavailable; your draft is unchanged")
	}
	_ = controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer controller.SetWriteDeadline(time.Time{})
	return c.JSON(http.StatusOK, result)
}
