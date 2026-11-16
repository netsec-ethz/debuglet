// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/assistantkeys"
	"github.com/netsec-ethz/debuglet/internal/studio"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type assistantState struct {
	client        *studio.Assistant
	slots         studioProxy
	requests      *rate.Limiter
	keys          *assistantkeys.Store
	personalModel string
	newPersonal   func(string) (*studio.Assistant, error)
}

// Assistant availability is independent of the compiler; proposals containing
// custom code require it. The provider receives source, never account credentials.
func Assistant(client *studio.Assistant) Option {
	return func(h *Handler) {
		h.assistant.client = client
		h.assistant.initialize()
	}
}

func (state *assistantState) initialize() {
	if state.requests == nil {
		state.slots = studioProxy{active: make(map[uuid.UUID]bool)}
		state.requests = rate.NewLimiter(rate.Every(10*time.Second), 4)
	}
}

func PersonalAssistantKeys(keys *assistantkeys.Store, model, reasoning string) Option {
	return func(h *Handler) {
		h.assistant.keys, h.assistant.personalModel = keys, model
		h.assistant.newPersonal = func(key string) (*studio.Assistant, error) { return studio.NewPersonalAssistant(model, key, reasoning) }
		h.assistant.initialize()
	}
}

func (h *Handler) registerAssistantRoutes(e *echo.Echo) {
	e.GET("/studio/assistant", h.assistantAvailability)
	e.POST("/studio/assistant", h.assistantReply)
	e.POST("/studio/assistant/stream", h.assistantReplyStream)
	e.GET("/me/assistant-key", h.assistantKeyStatus)
	e.PUT("/me/assistant-key", h.assistantKeySave)
	e.DELETE("/me/assistant-key", h.assistantKeyDelete)
	e.POST("/me/assistant-key/test", h.assistantKeyTest)
}

func assistantRoute(c echo.Context) error {
	if c.Request().URL.EscapedPath() != c.Path() || c.Request().URL.RawQuery != "" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "assistant routes do not accept encoded paths or query parameters")
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return nil
}

func (h *Handler) assistantAvailability(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if err := assistantRoute(c); err != nil {
		return err
	}
	result := struct {
		Enabled             bool   `json:"enabled"`
		Model               string `json:"model,omitempty"`
		Source              string `json:"source"`
		PersonalKeysEnabled bool   `json:"personal_keys_enabled"`
	}{Source: "none", PersonalKeysEnabled: h.assistant.keys != nil}
	if h.assistant.keys != nil {
		configured, err := h.assistant.keys.Configured(c.Request().Context(), account.UserUUID)
		if err != nil {
			return assistantKeyFailure()
		}
		if configured {
			result.Enabled, result.Source, result.Model = true, "personal", h.assistant.personalModel
			return c.JSON(http.StatusOK, result)
		}
	}
	if h.assistant.client != nil {
		result.Enabled, result.Source = true, "operator"
		result.Model = h.assistant.client.Model()
	}
	return c.JSON(http.StatusOK, result)
}

func (h *Handler) assistantReply(c echo.Context) error {
	return h.assistantReplyWithProgress(c, false)
}

func (h *Handler) assistantReplyStream(c echo.Context) error {
	return h.assistantReplyWithProgress(c, true)
}

func (h *Handler) assistantReplyWithProgress(c echo.Context, stream bool) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if err := assistantRoute(c); err != nil {
		return err
	}
	client, personal, err := h.assistantClient(c.Request().Context(), account.UserUUID)
	if err != nil {
		return err
	}
	if client == nil {
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, "experiment assistance is not enabled on this dispatcher")
	}
	if personal {
		defer client.Close()
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
	if stream {
		return h.streamAssistant(c, ctx, cancel, client, input, h.assistantCompileCheck(account.UserUUID))
	}
	started := time.Now()
	result, err := client.ReplyChecked(ctx, input, h.assistantCompileCheck(account.UserUUID))
	if err != nil {
		h.logAssistantFailure(c, err, ctx.Err(), time.Since(started))
		var compilerFailure *echo.HTTPError
		if errors.As(err, &compilerFailure) {
			if compilerFailure.Code == http.StatusTooManyRequests {
				c.Response().Header().Set("Retry-After", "1")
			}
			return compilerFailure
		}
		return assistantFailure(err, ctx.Err())
	}
	_ = controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer controller.SetWriteDeadline(time.Time{})
	return c.JSON(http.StatusOK, result)
}

// Progress is emitted by the generation/validation pipeline itself. The final
// proposal has the same checks and shape as the ordinary JSON response.
type assistantStreamEvent struct {
	Type         string                    `json:"type"`
	Stage        string                    `json:"stage,omitempty"`
	Phase        string                    `json:"phase,omitempty"`
	SummaryDelta string                    `json:"summary_delta,omitempty"`
	OutputBytes  int                       `json:"output_bytes,omitempty"`
	Result       *studio.AssistantResponse `json:"result,omitempty"`
	Error        *ErrorResponse            `json:"error,omitempty"`
	Status       int                       `json:"status,omitempty"`
}

func (h *Handler) streamAssistant(c echo.Context, ctx context.Context, cancel context.CancelFunc, client *studio.Assistant, input studio.AssistantRequest, check studio.AssistantCompileCheck) error {
	started := time.Now()
	c.Response().Header().Set("Content-Type", "text/event-stream")
	c.Response().Header().Set("X-Accel-Buffering", "no")
	controller := http.NewResponseController(c.Response().Writer)
	var writeMu sync.Mutex
	writeFailed := false
	write := func(record string) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := c.Request().Context().Err(); err != nil {
			return err
		}
		_ = controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
		defer controller.SetWriteDeadline(time.Time{})
		_, err := fmt.Fprint(c.Response(), record)
		if err == nil {
			err = controller.Flush()
		}
		if err != nil {
			writeFailed = true
			cancel()
		}
		return err
	}
	send := func(event assistantStreamEvent) error {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		return write("data: " + string(data) + "\n\n")
	}
	stopKeepalive := startAssistantKeepalive(ctx, 15*time.Second, func() error {
		return write(": keepalive\n\n")
	})
	result, err := client.ReplyProgress(ctx, input, check, func(progress studio.AssistantProgress) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if progress.Stage != "" {
			return send(assistantStreamEvent{Type: "stage", Stage: progress.Stage})
		}
		return send(assistantStreamEvent{Type: "provider_progress", Phase: progress.Phase, SummaryDelta: progress.SummaryDelta, OutputBytes: progress.OutputBytes})
	})
	stopKeepalive() // Join all comment writes before examining state or ending the stream.
	if err != nil {
		h.logAssistantFailure(c, err, ctx.Err(), time.Since(started))
	}
	if writeFailed || c.Request().Context().Err() != nil {
		return nil // A disconnected reader must not leave provider work running.
	}
	if err != nil {
		var public *echo.HTTPError
		if !errors.As(err, &public) {
			public = assistantFailure(err, ctx.Err())
		}
		status, body, _ := errorEnvelope(public)
		return send(assistantStreamEvent{Type: "error", Error: &body, Status: status})
	}
	return send(assistantStreamEvent{Type: "result", Result: &result})
}

// SSE comments keep an otherwise idle connection alive without inventing work
// stages. The returned function waits for any in-flight write to finish.
func startAssistantKeepalive(ctx context.Context, interval time.Duration, send func() error) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				if err := send(); err != nil {
					return
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// Streaming failures happen after the HTTP response has begun, so they cannot
// pass through errorHandler. Keep the same bounded diagnostics for both routes.
func (h *Handler) logAssistantFailure(c echo.Context, err, contextErr error, elapsed time.Duration) {
	if h.logger == nil {
		return
	}
	var public *echo.HTTPError
	if !errors.As(err, &public) {
		public = assistantFailure(err, contextErr)
	}
	_, body, _ := errorEnvelope(public)
	reason := body.Reason
	switch reason {
	case "provider_auth", "provider_rate_limit", "provider_unavailable", "output_truncated", "invalid_response", "invalid_graph", "deadline_exceeded", "canceled", "compiler_busy", "compiler_unavailable":
	default:
		reason = "unknown"
	}
	providerStatus := 0
	var failure *studio.AssistantError
	if errors.As(err, &failure) && failure.ProviderStatus >= 100 && failure.ProviderStatus <= 599 {
		providerStatus = failure.ProviderStatus
	}
	if failure != nil {
		for _, diagnostic := range failure.ValidationDiagnostics() {
			h.logger.Warn("Assistant proposal rejected",
				zap.String("request_id", daemonlog.RequestID(c.Request().Context())),
				zap.Int("attempt", diagnostic.Attempt), zap.String("stage", diagnostic.Stage),
				zap.String("diagnostic", diagnostic.Diagnostic))
		}
	}
	h.logger.Warn("Assistant request failed",
		zap.String("request_id", daemonlog.RequestID(c.Request().Context())),
		zap.String("reason", reason), zap.Int("provider_status", providerStatus),
		zap.Duration("latency", elapsed))
}

func assistantFailure(err, contextErr error) *echo.HTTPError {
	reason := "provider_unavailable"
	var failure *studio.AssistantError
	if errors.As(err, &failure) {
		reason = failure.Code
	} else if errors.Is(err, studio.ErrAssistantInvalidReply) {
		reason = "invalid_response"
	} else if errors.Is(err, studio.ErrAssistantTimeout) {
		reason = "deadline_exceeded"
	}
	if errors.Is(contextErr, context.DeadlineExceeded) {
		reason = "deadline_exceeded"
	} else if errors.Is(contextErr, context.Canceled) {
		reason = "canceled"
	}
	status, code := http.StatusBadGateway, CodeUnavailable
	var message string
	switch reason {
	case "provider_auth":
		message = "the AI provider rejected the selected credential or model access; update your personal key or contact the operator"
	case "provider_rate_limit":
		message = "the AI provider is at its usage limit; try again later"
	case "output_truncated":
		status, code = http.StatusUnprocessableEntity, CodeInvalidRequest
		message = "the AI reached its generation limit before finishing; retry or ask for a smaller change"
	case "invalid_response", "invalid_graph":
		status, code = http.StatusUnprocessableEntity, CodeInvalidRequest
		message = "the AI could not produce a valid experiment; try a smaller change or a template"
	case "deadline_exceeded":
		status = http.StatusGatewayTimeout
		message = "the AI did not finish in time; try again or start from a template"
	case "canceled":
		status = http.StatusGatewayTimeout
		message = "the AI request was canceled"
	default:
		reason = "provider_unavailable"
		message = "the AI provider is unavailable; try again later"
	}
	return echo.NewHTTPError(status, ErrorResponse{Code: code, Reason: reason, Message: message + "; your draft is unchanged"})
}
