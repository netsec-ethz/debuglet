// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"debuglet/internal/dispatcher"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type Handler struct {
	dispatcher *dispatcher.Dispatcher
	logger     *zap.Logger
	db         *sql.DB
}

func NewHandler(d *dispatcher.Dispatcher, db *sql.DB, l *zap.Logger) *Handler {
	return &Handler{
		dispatcher: d,
		db:         db,
		logger:     l,
	}
}

func (h *Handler) GetVersion(c echo.Context) error {
	return c.JSON(http.StatusOK, VersionResponse{Version: h.dispatcher.GetVersion()})
}

func (h *Handler) RegisterRoutes(e *echo.Echo) {
	e.Use(InsecureAuthMiddleware(h.db, h.logger))

	e.GET("/version", h.GetVersion)
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
