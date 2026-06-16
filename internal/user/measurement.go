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
)

const baseURL = "localhost:9000"

func CreateMeasurement(wasmPath string, numDebuglets int, spec api.DebugletRequest) []string {
	dat, err := os.ReadFile(wasmPath)
	if err != nil {
		panic(err)
	}
	wasm := base64.StdEncoding.EncodeToString(dat)
	spec.Wasm = wasm

	var debuglets []api.DebugletRequest
	for range numDebuglets {
		debuglets = append(debuglets, spec)
	}

	data, err := json.Marshal(debuglets)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf("http://%s/debuglet", baseURL)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{}
	resp, err := client.Do(req)
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

func AbortDebuglet(ID, executorID string) int {
	var delete api.DebugletDeleteRequest = api.DebugletDeleteRequest{
		DebugletID: ID,
		ExecutorID: executorID,
	}
	data, err := json.Marshal(delete)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf("http://%s/debuglet", baseURL)
	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Aborted '%s', got status=%d\n", ID, resp.StatusCode)
	return resp.StatusCode
}

func ReadOutput(debugletID string) error {
	url := fmt.Sprintf("http://%s/debuglet/%s", baseURL, debugletID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, body)
	}
	reader := bufio.NewReader(resp.Body)
	var event api.SSEEvent

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		// Empty line signals end of an event
		if line == "" {
			if len(event.Data) != 0 {
				handleEvent(debugletID, event)
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
	return nil
}

func handleEvent(debugletID string, e api.SSEEvent) {
	fmt.Printf("[[%s]]: [%s] Event: %s - Data Len: %d\n", debugletID, e.ID, e.Event, len(e.Data))
}
