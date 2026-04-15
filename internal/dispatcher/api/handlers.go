// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"encoding/base64"
	"net/http"
	"sync"

	"debuglet/internal/dispatcher"
	pb "debuglet/protocol"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type Handler struct {
	dispatcher *dispatcher.Dispatcher
	logger     *zap.Logger
	mu         sync.Mutex
}

func NewHandler(d *dispatcher.Dispatcher, l *zap.Logger) *Handler {
	return &Handler{dispatcher: d, logger: l}
}

// Register all routes
func (h *Handler) RegisterRoutes(e *echo.Echo) {
	e.GET("/executors", h.GetExecutors)
	e.POST("/measurements", h.CreateMeasurement)
	e.GET("/measurements/:id/start", h.StartMeasurementStream)
}

// GET /executors
func (h *Handler) GetExecutors(c echo.Context) error {
	executors := h.dispatcher.ListExecutors()
	return c.JSON(http.StatusOK, executors)
}

// POST /measurements
func (h *Handler) CreateMeasurement(c echo.Context) error {
	var req MeasurementRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}

	numDebuglets := len(req.Debuglets)
	if numDebuglets == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no debuglets provided")
	}
	measurementId, measurement := h.dispatcher.CreateMeasurement(numDebuglets)
	h.logger.Info("created measurement", zap.String("measurement_id", measurementId))
	for _, db := range req.Debuglets {
		sessionId := uuid.New().String()
		code, err := base64.StdEncoding.DecodeString(db.Code)
		if err != nil {
			h.logger.Error("failed to decode wasm code", zap.Error(err))
			return echo.NewHTTPError(http.StatusBadRequest, "invalid wasm code")
		}
		assignment := pb.DebugletAssignment{
			SessionId:     sessionId,
			MeasurementId: measurementId,
			Code:          code,
			Addresses:     db.Addresses,
			Policy: &pb.DebugletAssignment_Policy{
				FloorBw:      db.Policy.FloorBW,
				CeilBw:       db.Policy.CeilBW,
				Timeout:      db.Policy.Timeout,
				Destinations: db.Policy.Destinations,
			},
		}

		if err := func() *echo.HTTPError {
			h.mu.Lock()
			defer h.mu.Unlock()

			err = h.dispatcher.CheckCapacity(db.ExecutorID, &assignment)
			if err != nil {
				h.logger.Error("insufficient capacity in executor", zap.Error(err))
				return echo.NewHTTPError(http.StatusServiceUnavailable, "insufficient capacity")
			}
			destinationUpdates, err := h.dispatcher.RegisterAssignment(db.ExecutorID, &assignment)
			if err != nil {
				h.logger.Error("failed to register assignment", zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			for executorID, updates := range destinationUpdates {
				h.dispatcher.UpdateDestinations(executorID, updates)
			}
			return nil
		}(); err != nil {
			return err
		}

		err = h.dispatcher.DispatchTask(db.ExecutorID, measurement, &assignment)
		if err != nil {
			h.logger.Error("failed to create measurement", zap.Error(err))
			h.dispatcher.RemoveMeasurement(measurementId)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}

	return c.JSON(http.StatusOK, measurementId)
}

// GET /measurements/:id/start
// Uses Server-Sent Events (SSE) to stream logs/results
func (h *Handler) StartMeasurementStream(c echo.Context) error {
	measurementId := c.Param("id")
	measurement := h.dispatcher.GetMeasurement(measurementId)
	if measurement == nil {
		return echo.NewHTTPError(http.StatusNotFound, "measurement not found")
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true }, // dev only}
	} // TODO: specify CORS origin
	conn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		h.logger.Error("failed to upgrade to websocket", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to upgrade to websocket")
	}
	h.logger.Info("WebSocket connected", zap.String("measurement_id", measurementId))
	defer conn.Close()

	// goroutine: read from client
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				if err != websocket.ErrCloseSent {
					h.logger.Warn("failed to read websocket message", zap.Error(err))
				} // else: normal closure
				return
			}

			switch string(msg) {
			case "start":
				h.logger.Info("received start event", zap.String("measurement_id", measurementId))
				if err := measurement.Start(); err != nil {
					h.logger.Error("failed to start measurement", zap.Error(err))
					conn.WriteMessage(websocket.TextMessage, []byte("error: "+err.Error()))
				}
			default:
				h.logger.Info("unknown event", zap.String("event", string(msg)))
			}
		}
	}()

	// Stream events
	for ev := range measurement.EventChan {
		if err := conn.WriteJSON(ev); err != nil {
			h.logger.Warn("failed to send websocket message", zap.Error(err))
			break
		}
	}

	// Close connection
	conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Measurement completed."))
	conn.Close()

	// Cleanup
	h.logger.Info("measurement stream ended", zap.String("measurement_id", measurementId))
	h.dispatcher.RemoveMeasurement(measurementId)
	return nil
}
