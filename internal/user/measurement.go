package measurement

import (
	"bytes"
	"context"
	"debuglet/internal/dispatcher/api"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

const baseURL = "localhost:9000"

func CreateMeasurement(wasmPath string, numDebuglets int, executorID string, floorBW, ceilBW, timeout int64, addresses []string) string {
	dat, err := os.ReadFile(wasmPath)
	if err != nil {
		panic(err)
	}
	wasm := base64.StdEncoding.EncodeToString(dat)

	var debuglets []api.DebugletRequest
	for range numDebuglets {
		debuglets = append(debuglets, api.DebugletRequest{
			ExecutorID: executorID,
			Code:       wasm,
			Addresses:  addresses,
			Policy: struct {
				FloorBW   int64 "json:\"floor_bw\""
				CeilBW    int64 "json:\"ceil_bw\""
				TimeoutMS int64 "json:\"timeout_ms\""
			}{
				FloorBW:   floorBW,
				CeilBW:    ceilBW,
				TimeoutMS: timeout,
			},
		})
	}

	req := api.MeasurementRequest{Debuglets: debuglets}
	data, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf("http://%s/measurements", baseURL)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	measurementID, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return strings.Trim(string(measurementID), "\"\n ")

}

func ConnectMeasurement(measurementID string) (start func(ctx context.Context)) {
	url := fmt.Sprintf("ws://%s/measurements/%s/start", baseURL, measurementID)
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		panic(err)
	}

	return func(ctx context.Context) {
		defer conn.Close()

		err := conn.WriteMessage(websocket.TextMessage, []byte("start"))
		if err != nil {
			panic(err)
		}

		for {
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				log.Printf("read error or connection closed (ID=%s): %v\n", measurementID, err)
				return
			}
			switch messageType {
			case websocket.TextMessage:
				log.Printf("received text (ID=%s): %s\n", measurementID, string(p))
			case websocket.CloseMessage:
				log.Printf("server closed the connection ID=%s\n", measurementID)
				return
			default:
				log.Println("got message:", messageType, p)
			}
		}
	}
}
