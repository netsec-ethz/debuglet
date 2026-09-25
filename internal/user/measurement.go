// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package user

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/api"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	DispatcherAddr = "localhost:9000"
	DispatcherTLS  = false
)

func dispatcherURL(path string) string {
	scheme := "http"
	if DispatcherTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, DispatcherAddr, path)
}

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

	tid, key := PaymentIntent(debuglets)

	debreq := api.SubmitDebugletsRequest{
		TransactionId: tid,
		AuthKey:       key,
		Debuglets:     debuglets,
	}

	data, err := json.Marshal(debreq)
	if err != nil {
		panic(err)
	}

	url := dispatcherURL("/debuglet")
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

func PaymentIntent(specs []api.DebugletRequest) (string, string) {
	intentReq := api.PaymentIntentRequest{
		Debuglets:     specs,
		PaymentMethod: "TEST",
	}
	data, err := json.Marshal(intentReq)
	if err != nil {
		panic(err)
	}

	url := dispatcherURL("/payment/intent")
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

	var intentResp api.IntentResponse
	if err := json.NewDecoder(resp.Body).Decode(&intentResp); err != nil {
		panic(err)
	}
	if intentResp.Method != "TEST" {
		panic(fmt.Errorf("unexpected payment method: %s", intentResp.Method))
	}
	if v, ok := intentResp.Intent.(map[string]any); ok {
		tid, ok := v["transaction_id"].(string)
		if !ok {
			panic(fmt.Errorf("unexpected transaction_id type: %T", v["transaction_id"]))
		}
		authKey, ok := v["auth_key"].(string)
		if !ok {
			panic(fmt.Errorf("unexpected auth_key type: %T", v["auth_key"]))
		}
		return tid, authKey
	}
	panic(fmt.Errorf("unexpected intent type: %T", intentResp.Intent))
}

func AbortDebuglet(ID, executorID string) int {
	uid, err := uuid.Parse(ID)
	if err != nil {
		panic(err)
	}
	var delete api.DebugletDeleteRequest = api.DebugletDeleteRequest{
		DebugletID: uid,
		ExecutorID: executorID,
	}
	data, err := json.Marshal(delete)
	if err != nil {
		panic(err)
	}

	url := dispatcherURL("/debuglet")
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
	after := int64(0)
	for {
		url := dispatcherURL(fmt.Sprintf("/debuglet/%s/logs?after=%d&limit=100", debugletID, after))
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		var logResp api.DebugletLogsResponse
		if err := json.NewDecoder(resp.Body).Decode(&logResp); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		for _, entry := range logResp.Logs {
			decoded, _ := base64.StdEncoding.DecodeString(entry.Output)
			fmt.Printf("[[%s]]: [%s] %s\n", debugletID, entry.Timestamp, strings.TrimSpace(string(decoded)))
		}

		if logResp.State == "RunStateExited" && !logResp.HasMore {
			return nil
		}
		after = logResp.After
		time.Sleep(2 * time.Second)
	}
}

func ReadState(debugletID string) (api.DebugletStateResponse, error) {
	url := dispatcherURL(fmt.Sprintf("/debuglet/%s/state", debugletID))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return api.DebugletStateResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return api.DebugletStateResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return api.DebugletStateResponse{}, fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, body)
	}

	var stateResp api.DebugletStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&stateResp); err != nil {
		return api.DebugletStateResponse{}, err
	}
	return stateResp, nil
}
