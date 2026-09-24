// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// Registered route paths. They are the public HTTP surface described by
// api/openapi.yaml; the two discovery routes are exempt from contract
// negotiation so that any client can read the contract.
const (
	routeVersion = "/version"
	routeOpenAPI = "/openapi.yaml"
	// The health routes are public and carry no run data; handlers_health.go
	// states what each of them answers.
	routeLiveness  = "/healthz"
	routeReadiness = "/readyz"
	routeHealth    = "/health"
)

// maxRequestBodyBytes bounds every request body the API reads. It is the bound
// pkg/client applies to the exact encoded envelopes it sends, so a request the
// SDK sends is never refused for its size.
const maxRequestBodyBytes = 32 << 20

type Handler struct {
	dispatcher *dispatcher.Dispatcher
	logger     *zap.Logger
	db         *sql.DB
	// localDevelopment enables the documented local development bypass. See
	// LocalDevelopment.
	localDevelopment bool
	// cookieSecure marks the session cookies Secure. See CookieSecure.
	cookieSecure bool
	// health holds the last health observation. See handlers_health.go.
	health healthMemo
}

// Option configures a Handler. Every option is explicit: the zero
// configuration is the profile a deployment gets, and nothing about it is
// inferred from the request.
type Option func(*Handler)

// LocalDevelopment enables the local development profile of this API. In it, a
// request that presents no credential at all is served as the dispatcher's own
// local operator, and its runs are recorded without an owner, which is what
// keeps the explicit wallet-free local flow usable without a browser. A
// request that does present a credential is authenticated and authorized
// normally even here.
//
// It is off by default and must never be enabled for a deployment that is
// reachable by anyone but its operator. cmd/dispatcher enables it exactly
// where it already recognises a local environment: blockchain payments
// disabled, the TLS listener disabled and both listeners on loopback, which is
// the configuration the local role commands generate and the deployment
// examples do not.
func LocalDevelopment(enabled bool) Option {
	return func(h *Handler) { h.localDevelopment = enabled }
}

// CookieSecure marks the session and CSRF cookies Secure, so a browser sends
// them over TLS only. It is an explicit statement by the deployment because a
// request cannot describe its own scheme: X-Forwarded-Proto, X-Url-Scheme and
// X-Forwarded-Ssl are set by whoever sent the request, and trusting them would
// let a plaintext caller decide that its own cookies need no TLS. cmd/dispatcher
// sets it when the daemon terminates TLS itself or when the configuration says
// a TLS terminator stands in front of it.
func CookieSecure(secure bool) Option {
	return func(h *Handler) { h.cookieSecure = secure }
}

func NewHandler(d *dispatcher.Dispatcher, db *sql.DB, l *zap.Logger, options ...Option) *Handler {
	h := &Handler{
		dispatcher: d,
		db:         db,
		logger:     l,
	}
	for _, option := range options {
		option(h)
	}
	return h
}

func (h *Handler) RegisterRoutes(e *echo.Echo) {
	// Every failure, including the ones Echo raises before a handler runs,
	// answers with the documented error envelope.
	e.HTTPErrorHandler = h.errorHandler
	e.Use(APIVersionMiddleware())
	e.Use(bodyLimitMiddleware())
	e.Use(AuthMiddleware(h.db, h.localDevelopment))

	// contract
	e.GET(routeVersion, h.GetVersion)
	e.GET(routeOpenAPI, h.GetOpenAPI)
	// health
	e.GET(routeLiveness, h.GetLiveness)
	e.GET(routeReadiness, h.GetReadiness)
	e.GET(routeHealth, h.GetHealth)
	// session
	e.POST("/auth/login", h.PostLogin)
	e.POST("/auth/logout", h.PostLogout)
	e.POST("/auth/recover", h.PostRecover)
	// debuglet
	e.PUT("/debuglet", h.PutDebuglets)
	e.GET("/debuglet/:id/logs", h.GetDebugletLogs)
	e.GET("/debuglet/:id/state", h.GetDebugletState)
	e.DELETE("/debuglet", h.DeleteDebuglet)
	// executor
	e.GET("/executors", h.GetExecutors)
	e.GET("/executors/by-ip", h.GetExecutorByIP)
	e.GET("/executors/:id/tesla", h.GetExecutorTesla)
	// destination
	e.PATCH("/destination", h.PatchDestinationLimit)
	// payment
	// e.GET("payment/balance", h.GetBalance)
	e.PUT("/payment/intent", h.PutPaymentIntent)
	e.GET("/payment/:transaction_id/status", h.GetPaymentStatus)
	// user
	e.GET("/me", h.GetMe)
	e.GET("/user-ids", h.ListUserIDs)
	e.PUT("/user", h.CreateUser)
	e.GET("/list-debuglets", h.ListUserDebuglets)
}

// bodyLimitMiddleware refuses a request body above maxRequestBodyBytes before
// any handler acts on it. A declared length above the limit is refused without
// reading the body. A body of unknown length is cut at the limit: the read that
// would pass it fails, so a handler's decode fails and never sees a byte beyond
// the limit, and that failure is reported as the same refusal.
func bodyLimitMiddleware() echo.MiddlewareFunc {
	message := "request body exceeds " + strconv.FormatInt(maxRequestBodyBytes, 10) + " bytes"
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			if req.ContentLength > maxRequestBodyBytes {
				return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, message)
			}
			req.Body = http.MaxBytesReader(c.Response().Writer, req.Body, maxRequestBodyBytes)
			err := next(c)
			var exceeded *http.MaxBytesError
			if errors.As(err, &exceeded) {
				return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, message)
			}
			return err
		}
	}
}
