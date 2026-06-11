package api

import (
	"debuglet/internal/dispatcher"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type Handler struct {
	dispatcher *dispatcher.Dispatcher
	logger     *zap.Logger
}

func NewHandler(d *dispatcher.Dispatcher, l *zap.Logger) *Handler {
	return &Handler{
		dispatcher: d,
		logger:     l,
	}
}

func (h *Handler) RegisterRoutes(e *echo.Echo) {
	// debuglet
	e.PUT("/debuglet", h.SubmitDebuglets)
	e.GET("/logs/:id", h.GetLogsWS)
	e.DELETE("/debuglet/:id", h.AbortDebuglet)
	// executor
	e.GET("/executors", h.GetExecutors)
	e.GET("/executors/by-ip", h.GetExecutorByIP)
	e.GET("/executors/:id/tesla", h.GetExecutorTesla)
	// payment
}
