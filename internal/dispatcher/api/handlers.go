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
	"io"
	"net/http"
	"sync"

	"debuglet/internal/dispatcher"
	"debuglet/pkg/tesla"
	pb "debuglet/protocol"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
	e.POST("/verify", h.Verify)
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
				FloorBw:   db.Policy.FloorBW,
				CeilBw:    db.Policy.CeilBW,
				TimeoutMs: db.Policy.TimeoutMS,
			},
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
				if err := h.dispatcher.StartMeasurement(measurement); err != nil {
					h.logger.Error("failed to start measurement", zap.Error(err))
					conn.WriteMessage(websocket.TextMessage, []byte("error: "+err.Error()))
				}
			default:
				h.logger.Info("unknown event", zap.String("event", string(msg)))
			}
		}
	}()

	// Stream events
	exitsReceived := 0
	for ev := range measurement.EventChan {
		if _, ok := ev.(dispatcher.ExitEvent); ok {
			exitsReceived++
			if exitsReceived == measurement.Len() {
				break
			}
			continue
		}
		if err := conn.WriteJSON(ev); err != nil {
			h.logger.Warn("failed to send websocket message", zap.Error(err))
			break
		}
	}

	// Close connection
	conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Measurement completed."))

	// Cleanup
	h.logger.Info("measurement stream ended", zap.String("measurement_id", measurementId))
	h.dispatcher.RemoveMeasurement(measurementId)
	return nil
}
// POST /verify
func (h *Handler) Verify(c echo.Context) error {
	measurementId := c.FormValue("measurement_id")
	if measurementId == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "measurement_id is required")
	}

	file, err := c.FormFile("pcap")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "pcap file is required")
	}

	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	pcapReader, err := pcapgo.NewReader(src)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid pcap file: "+err.Error())
	}

	type result struct {
		Timestamp string `json:"timestamp"`
		SourceIP  string `json:"source_ip"`
		DestIP    string `json:"dest_ip"`
		Tag       uint16 `json:"tag"`
		Valid     bool   `json:"valid"`
		Error     string `json:"error,omitempty"`
	}
	var results []result

	for {
		data, ci, err := pcapReader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			h.logger.Error("failed to read packet", zap.Error(err))
			break
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		executorId := h.dispatcher.GetExecutorByIP(ip.SrcIP.String())
		if executorId == "" {
			results = append(results, result{
				Timestamp: ci.Timestamp.String(),
				SourceIP:  ip.SrcIP.String(),
				DestIP:    ip.DstIP.String(),
				Tag:       ip.Id,
				Valid:     false,
				Error:     "unknown executor",
			})
			continue
		}

		// Infer epoch from packet timestamp.
		// Note: This assumes the dispatcher's view of time matches the executor's epoch 0.
		// In a production system, epoch 0 is usually a fixed wall-clock time.
		// Here we assume epoch duration of 1 hour for simplicity if not specified.
		// Ideally the KeyStore would handle time-based lookup.
		epoch := ci.Timestamp.Unix() / 3600

		key, ok := h.dispatcher.KeyStore.Get(executorId, measurementId, epoch)
		if !ok {
			// Try previous epoch just in case of clock drift
			key, ok = h.dispatcher.KeyStore.Get(executorId, measurementId, epoch-1)
		}

		if !ok {
			results = append(results, result{
				Timestamp: ci.Timestamp.String(),
				SourceIP:  ip.SrcIP.String(),
				DestIP:    ip.DstIP.String(),
				Tag:       ip.Id,
				Valid:     false,
				Error:     "key not found",
			})
			continue
		}

		valid, err := tesla.VerifyBPFTag(key, epoch, []byte(measurementId), ip.BaseLayer.Contents, ip.Id)
		results = append(results, result{
			Timestamp: ci.Timestamp.String(),
			SourceIP:  ip.SrcIP.String(),
			DestIP:    ip.DstIP.String(),
			Tag:       ip.Id,
			Valid:     valid,
		})
	}

	return c.JSON(http.StatusOK, results)
}
