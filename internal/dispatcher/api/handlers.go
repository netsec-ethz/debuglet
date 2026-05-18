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
	"strconv"
	"sync"
	"time"

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
	e.GET("/executors/by-ip", h.GetExecutorByIP)
	e.GET("/executors/:id/tesla", h.GetExecutorTesla)
	e.POST("/measurements", h.CreateMeasurement)
	e.GET("/measurements/:id/start", h.StartMeasurementStream)
	e.POST("/verify", h.Verify)
}

// GET /executors
func (h *Handler) GetExecutors(c echo.Context) error {
	executors := h.dispatcher.ListExecutors()
	return c.JSON(http.StatusOK, executors)
}

// GET /executors/by-ip?ip=<ip>[&n=<count>]
//
// Returns the executor ID and the last n measurement IDs dispatched to the
// executor whose source IP matches the query parameter. n defaults to 10 and
// can be overridden by the caller.
func (h *Handler) GetExecutorByIP(c echo.Context) error {
	ip := c.QueryParam("ip")
	if ip == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ip query parameter is required")
	}

	// Parse optional ?n= limit.
	n := 0
	if nStr := c.QueryParam("n"); nStr != "" {
		parsed, err := strconv.Atoi(nStr)
		if err != nil || parsed <= 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "n must be a positive integer")
		}
		n = parsed
	}

	exec := h.dispatcher.GetExecutorByIPFull(ip)
	if exec == nil {
		return echo.NewHTTPError(http.StatusNotFound, "no executor found for IP "+ip)
	}

	return c.JSON(http.StatusOK, ExecutorByIPResponse{
		ExecutorID:     exec.ID,
		MeasurementIDs: exec.RecentMeasurementIDs(n),
	})
}

// GET /executors/:id/tesla
//
// Returns the TESLA key schedule parameters for the given executor, including
// the public anchor key k_0 and the latest disclosed key k_τ. External
// verifiers use these to reconstruct chain keys and validate packet tags.
func (h *Handler) GetExecutorTesla(c echo.Context) error {
	id := c.Param("id")
	exec := h.dispatcher.GetExecutor(id)
	if exec == nil {
		return echo.NewHTTPError(http.StatusNotFound, "executor not found: "+id)
	}

	resp := ExecutorTeslaResponse{
		ExecutorID:        exec.ID,
		AnchorTimestampNs: exec.TeslaAnchorTimestampNs,
		DelaySec:          exec.TeslaDelaySec,
	}
	if len(exec.TeslaAnchorKey) > 0 {
		resp.AnchorKey = base64.StdEncoding.EncodeToString(exec.TeslaAnchorKey)
	}

	// Attach the latest disclosed key if one exists.
	if epoch, key, ok := h.dispatcher.KeyStore.LatestDisclosed(id); ok {
		resp.DisclosedEpoch = epoch
		resp.DisclosedKey = base64.StdEncoding.EncodeToString(key)
	}

	return c.JSON(http.StatusOK, resp)
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

	// Print all keys for debugging
	h.dispatcher.KeyStore.PrintKeys()
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
			h.logger.Error("unknown executor", zap.String("source_ip", ip.SrcIP.String()))
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

		// Infer epoch from packet timestamp using the executor's synchronized Tesla parameters.
		exec := h.dispatcher.GetExecutor(executorId)
		if exec == nil || exec.TeslaDelaySec == 0 {
			results = append(results, result{
				Timestamp: ci.Timestamp.String(),
				SourceIP:  ip.SrcIP.String(),
				DestIP:    ip.DstIP.String(),
				Tag:       ip.Id,
				Valid:     false,
				Error:     "executor tesla config not found",
			})
			continue
		}

		anchor := time.Unix(0, exec.TeslaAnchorTimestampNs)
		delay := time.Duration(exec.TeslaDelaySec) * time.Second
		elapsed := ci.Timestamp.Sub(anchor)
		epoch := int64(1)
		if elapsed > 0 {
			epoch = int64(elapsed/delay) + 1
		}

		// Reconstruct the full IPv4 packet (header + payload)
		ipPacketBytes := make([]byte, len(ip.BaseLayer.Contents)+len(ip.BaseLayer.Payload))
		copy(ipPacketBytes, ip.BaseLayer.Contents)
		copy(ipPacketBytes[len(ip.BaseLayer.Contents):], ip.BaseLayer.Payload)

		// Define a helper to retrieve or derive the key for any target epoch.
		// In the backward chain, a later disclosed key can derive an earlier epoch key.
		deriveKeyForEpoch := func(targetEpoch int64) ([]byte, bool) {
			if k, ok := h.dispatcher.KeyStore.Get(executorId, targetEpoch); ok {
				return k, true
			}
			// Walk from higher disclosed epochs downward to find one we can
			// hash forward to reach targetEpoch.
			if latestEpoch, latestKey, ok := h.dispatcher.KeyStore.LatestDisclosed(executorId); ok {
				if latestEpoch >= targetEpoch {
					derived, err := tesla.DeriveFromDisclosed(latestKey, latestEpoch, targetEpoch)
					if err == nil {
						return derived, true
					}
				}
			}
			return nil, false
		}

		var valid bool
		var ok bool

		// Try to verify with target epoch
		key, ok := deriveKeyForEpoch(epoch)
		if ok {
			valid, _ = tesla.VerifyBPFTag(key, epoch, []byte(measurementId), ipPacketBytes, ip.Id)
		}

		// If verify failed or key wasn't found, try epoch-1 as clock-drift fallback
		if !valid || !ok {
			if prevKey, okPrev := deriveKeyForEpoch(epoch - 1); okPrev {
				validPrev, errPrev := tesla.VerifyBPFTag(prevKey, epoch-1, []byte(measurementId), ipPacketBytes, ip.Id)
				if errPrev == nil && validPrev {
					valid = true
					ok = true
				}
			}
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
