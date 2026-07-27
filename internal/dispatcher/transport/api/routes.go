package api

import (
	"debuglet/internal/dispatcher"
	"debuglet/internal/dispatcher/db"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type Handler struct {
	dispatcher *dispatcher.Dispatcher
	logger     *zap.Logger
	database 	*db.UserDB
}

func NewHandler(d *dispatcher.Dispatcher, db *db.UserDB, l *zap.Logger) *Handler {
	return &Handler{
		dispatcher: d,
		logger:     l,
		database: db,
	}
}

func (h *Handler) GetVersion(c echo.Context) error {
	return c.JSON(http.StatusOK, VersionResponse{Version: h.dispatcher.GetVersion()})
}

func (h *Handler) RegisterRoutes(e *echo.Echo) {
	e.GET("/version", h.GetVersion)
	// debuglet
	e.PUT("/debuglet", h.SubmitDebuglets)
	e.GET("/debuglet/:id", h.GetLogsSSE)
	e.GET("/debuglet/:id/state", h.GetDebugletState)
	e.DELETE("/debuglet", h.DeleteDebuglet)
	// executor
	e.GET("/executors", h.GetExecutors)
	e.GET("/executors/by-ip", h.GetExecutorByIP)
	e.GET("/executors/:id/tesla", h.GetExecutorTesla)
	// destination
	e.PATCH("/destination", h.UpdateDestinationLimit)
	// payment
	e.GET("payment/balance", h.GetBalance)
	//authentication
	e.GET("auth/nonce", h.GetNonce)
	e.PUT("auth/verify", h.Verify)
}
