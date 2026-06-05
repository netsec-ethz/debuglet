package user

import (
	"bytes"
	"context"
	"debuglet/internal/dispatcher/transport/api"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/websocket"
)

const baseURL = "localhost:9000"

func CreateMeasurement(wasmPath string, numDebuglets int, executorID string, floorBW, ceilBW, timeout int64, addresses []string) []string {
	dat, err := os.ReadFile(wasmPath)
	if err != nil {
		panic(err)
	}
	wasm := base64.StdEncoding.EncodeToString(dat)

	var debuglets []api.DebugletRequest
	for range numDebuglets {
		debuglets = append(debuglets, api.DebugletRequest{
			ExecutorID: executorID,
			Wasm:       wasm,
			Policy: api.DebugletPolicy{
				FloorBW:   floorBW,
				CeilBW:    ceilBW,
				TimeoutMS: timeout,
				Addresses: addresses,
			},
		})
	}

	data, err := json.Marshal(debuglets)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf("http://%s/submit", baseURL)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		panic(fmt.Errorf("... %s", body))
	}

	var ids []string
	if err := json.NewDecoder(resp.Body).Decode(&ids); err != nil {
		panic(err)
	}
	return ids

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
