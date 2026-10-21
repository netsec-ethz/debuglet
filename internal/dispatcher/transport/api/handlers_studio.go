// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
)

const (
	studioWorkflowLimit      = 1 << 20
	studioExperimentLimit    = 4 << 20
	studioResponseLimit      = 32 << 20
	studioConcurrentRequests = 4
	// The worker owns its six-minute compiler deadline. The extra interval
	// lets it report that outcome, while bounding a stalled worker as well.
	studioRequestTimeout = 6*time.Minute + 10*time.Second
)

type studioProxy struct {
	client       *http.Client
	timeout      time.Duration
	writeTimeout time.Duration
	mu           sync.Mutex
	active       map[uuid.UUID]bool
}

// Studio connects only to the configured Unix socket. No URL, compiler path,
// credential, or other worker option comes from a browser request.
func Studio(cfg config.StudioConfig) Option {
	return func(h *Handler) {
		if cfg.SocketPath == "" {
			return
		}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", cfg.SocketPath)
			},
			DisableCompression:     true,
			MaxIdleConns:           studioConcurrentRequests,
			MaxIdleConnsPerHost:    studioConcurrentRequests,
			IdleConnTimeout:        30 * time.Second,
			MaxResponseHeaderBytes: 16 << 10,
		}
		h.studio = &studioProxy{
			client:       &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
			timeout:      studioRequestTimeout,
			writeTimeout: 30 * time.Second,
			active:       make(map[uuid.UUID]bool),
		}
	}
}

func (h *Handler) registerStudioRoutes(e *echo.Echo) {
	e.GET("/studio/catalog", h.proxyStudio)
	e.POST("/studio/validate", h.proxyStudio)
	e.POST("/studio/build", h.proxyStudio)
	e.POST("/studio/experiments/validate", h.proxyStudio)
	e.POST("/studio/experiments/build", h.proxyStudio)
}

// acquire never queues: the map contains only active accounts, with one
// request per account and at most four globally, and is emptied on completion.
func (p *studioProxy) acquire(id uuid.UUID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active[id] || len(p.active) >= studioConcurrentRequests {
		return false
	}
	p.active[id] = true
	return true
}

func (p *studioProxy) release(id uuid.UUID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.active, id)
}

func (h *Handler) proxyStudio(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	req := c.Request()
	// Do not turn this into a generic reverse proxy: encoded route aliases,
	// query options, and every other method/path are outside this interface.
	if req.URL.EscapedPath() != c.Path() || req.URL.RawQuery != "" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "studio routes do not accept encoded paths or query parameters")
	}
	if h.studio == nil {
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, "hosted compilation is not enabled on this dispatcher")
	}
	if !h.studio.acquire(account.UserUUID) {
		c.Response().Header().Set("Retry-After", "1")
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "hosted compiler is busy; retry shortly")
	}
	defer h.studio.release(account.UserUUID)
	ctx, cancel := context.WithTimeout(req.Context(), h.studio.timeout)
	defer cancel()
	var body []byte
	if req.Method == http.MethodPost {
		if err := h.allowAdmissionRequest(c, account); err != nil {
			return err
		}
		mediaType, _, err := mime.ParseMediaType(req.Header.Get(echo.HeaderContentType))
		if err != nil || mediaType != echo.MIMEApplicationJSON || req.Header.Get("Content-Encoding") != "" {
			return apiError(http.StatusUnsupportedMediaType, CodeUnsupportedMediaType, "studio request body must be uncompressed application/json")
		}
		limit := int64(studioWorkflowLimit)
		if c.Path() == "/studio/experiments/validate" || c.Path() == "/studio/experiments/build" {
			limit = studioExperimentLimit
		}
		if req.ContentLength > limit {
			return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "studio request body exceeds its size limit")
		}
		// Bound slow uploads as well as bytes; a context deadline alone does
		// not interrupt a server-side request Body.Read.
		controller := http.NewResponseController(c.Response().Writer)
		_ = controller.SetReadDeadline(time.Now().Add(30 * time.Second))
		body, err = io.ReadAll(http.MaxBytesReader(c.Response().Writer, req.Body, limit))
		if err != nil {
			var oversized *http.MaxBytesError
			if errors.As(err, &oversized) {
				return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "studio request body exceeds its size limit")
			}
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "could not read studio request body")
		}
		_ = controller.SetReadDeadline(time.Time{})
	}
	upstream, err := http.NewRequestWithContext(ctx, req.Method, "http://studio"+c.Path(), bytes.NewReader(body))
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "could not prepare studio request", err)
	}
	// Intentionally construct fresh headers: cookies, authorization, CSRF,
	// forwarded identities and local Studio tokens never reach the worker.
	upstream.Header.Set("Accept", echo.MIMEApplicationJSON)
	upstream.Header.Set("User-Agent", "")
	if req.Method == http.MethodPost {
		upstream.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	response, err := h.studio.client.Do(upstream)
	if err != nil {
		return studioTransportError(ctx, err)
	}
	defer response.Body.Close()
	if response.ContentLength > studioResponseLimit {
		return apiError(http.StatusBadGateway, CodeUnavailable, "hosted compiler response exceeds its size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, studioResponseLimit+1))
	if err != nil {
		return studioTransportError(ctx, err)
	}
	if len(data) > studioResponseLimit {
		return apiError(http.StatusBadGateway, CodeUnavailable, "hosted compiler response exceeds its size limit")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get(echo.HeaderContentType))
	if err != nil || mediaType != echo.MIMEApplicationJSON || !json.Valid(data) || !studioResponseStatus(response.StatusCode) {
		return apiError(http.StatusBadGateway, CodeUnavailable, "hosted compiler returned an invalid response")
	}
	// No upstream cookies, redirects, encodings or other response headers are
	// trusted by the browser. Do not cache generated programs or diagnostics.
	c.Response().Header().Set("Cache-Control", "no-store")
	if response.StatusCode == http.StatusTooManyRequests {
		c.Response().Header().Set("Retry-After", "1")
	}
	// A slow browser must not hold an admission slot indefinitely after the
	// worker has finished. The upstream context does not interrupt this write.
	controller := http.NewResponseController(c.Response().Writer)
	_ = controller.SetWriteDeadline(time.Now().Add(h.studio.writeTimeout))
	defer controller.SetWriteDeadline(time.Time{})
	return c.Blob(response.StatusCode, echo.MIMEApplicationJSON, data)
}

func studioTransportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return apiErrorFrom(http.StatusGatewayTimeout, CodeUnavailable, "hosted compiler request timed out or was canceled", err)
	}
	return apiErrorFrom(http.StatusServiceUnavailable, CodeUnavailable, "hosted compiler is unavailable; retry shortly", err)
}

func studioResponseStatus(status int) bool {
	switch status {
	case http.StatusOK, http.StatusBadRequest, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity,
		http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
