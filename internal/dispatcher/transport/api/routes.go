package api

import (
	"debuglet/internal/dispatcher"
	"net/http"

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

func (h *Handler) GetVersion(c echo.Context) error {
	return c.JSON(http.StatusOK, VersionResponse{Version: h.dispatcher.GetVersion()})
}

func (h *Handler) RegisterRoutes(e *echo.Echo) {
	e.GET("/version", h.GetVersion)
	// debuglet
	e.PUT("/debuglet", h.PutDebuglets)
	e.GET("/debuglet/:id", h.GetLogsSSE)
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
}
