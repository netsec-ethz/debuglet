package user

import (
	"bufio"
	"bytes"
	"debuglet/internal/dispatcher/transport/api"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const baseURL = "localhost:9000"

func CreateMeasurement(wasmPath string, numDebuglets int, executorID string, floorBW, ceilBW int64, timeout time.Duration, addresses []string) []string {
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
			Policy: api.DebugletPolicyRequest{
				FloorBW:   floorBW,
				CeilBW:    ceilBW,
				TimeoutMS: timeout.Milliseconds(),
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

func ReadOutput(debugletID string) {
	client := &http.Client{
		Timeout: 0,
	}

	url := fmt.Sprintf("http://%s/logs/%s", baseURL, debugletID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		panic(fmt.Sprintf("unexpected status: %d, body: %s", resp.StatusCode, body))
	}
	reader := bufio.NewReader(resp.Body)
	var event api.SSEEvent

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		// Empty line signals end of an event
		if line == "" {
			if len(event.Data) != 0 {
				handleEvent(event)
				event = api.SSEEvent{}
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "id:"):
			event.ID = []byte(strings.TrimSpace(line[3:]))
		case strings.HasPrefix(line, "event:"):
			event.Event = []byte(strings.TrimSpace(line[6:]))
		case strings.HasPrefix(line, "retry:"):
			fmt.Sscanf(line[6:], "%d", &event.Retry)
		case strings.HasPrefix(line, "data:"):
			if len(event.Data) != 0 {
				event.Data = append(event.Data, '\n')
			}
			event.Data = append(event.Data, strings.TrimSpace(line[5:])...)
		}
	}
}

func handleEvent(e api.SSEEvent) {
	fmt.Printf("[%s] Event: %s\n  Data: %s\n", e.ID, e.Event, e.Data)
}
