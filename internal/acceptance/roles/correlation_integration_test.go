//go:build linux && roles_integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package roles

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

// Use the installed daemons and negotiated transport. A future start keeps
// the real WASM queued until the HTTP cancellation joins its removal.
func assertRunCorrelation(t *testing.T, ctx context.Context, c *client.Client, d, e *role, wasmPath string) {
	t.Helper()
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(time.Hour).Unix()
	batch, err := client.Prepare([]client.Request{{OrderID: 1, ExecutorID: e.record.ExecutorID, StartTimestamp: &start, Wasm: wasm, Policy: client.Policy{TimeoutMS: 1000, FloorBW: 64000, CeilBW: 64000, Addresses: []string{"127.0.0.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	submitted, err := c.SubmitTEST(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	id := submitted.IDs[0]
	if err := c.Cancel(ctx, id, e.record.ExecutorID); err != nil {
		t.Fatal(err)
	}
	state, err := c.Status(ctx, id)
	if err != nil || state.State != client.StateExited {
		t.Fatalf("cancelled run: %+v %v", state, err)
	}
	phase, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	read := func(r *role) []map[string]any {
		t.Helper()
		data, err := readRegular(filepath.Join(r.state, r.kind+".log"), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		var entries []map[string]any
		// Only complete lines are observable while the process is still writing.
		lines := bytes.Split(data, []byte{'\n'})
		for _, line := range lines[:len(lines)-1] {
			if len(line) == 0 {
				continue
			}
			var entry map[string]any
			if err := json.Unmarshal(line, &entry); err != nil {
				t.Fatalf("daemon log is not JSON: %v", err)
			}
			entries = append(entries, entry)
		}
		return entries
	}
	find := func(entries []map[string]any, message string) map[string]any {
		for _, entry := range entries {
			if entry["msg"] == message && entry["run_id"] == id {
				return entry
			}
		}
		return nil
	}
	for {
		dispatcherLogs, executorLogs := read(d), read(e)
		admitted := find(dispatcherLogs, "Run admitted")
		cancelled := find(dispatcherLogs, "Cancellation recorded")
		accepted := find(executorLogs, "Run accepted")
		joined := find(executorLogs, "Run cancellation joined")
		if admitted != nil && cancelled != nil && accepted != nil && joined != nil {
			for _, entry := range []map[string]any{admitted, cancelled, accepted, joined} {
				for _, key := range []string{"executor_id", "dispatcher_incarnation", "session_id"} {
					if entry[key] != admitted[key] {
						t.Fatalf("broken %s correlation: %+v", key, entry)
					}
				}
				if entry["attempt"] != "unknown" {
					t.Fatal("log invented attempt identity")
				}
			}
			if admitted["executor_id"] != e.record.ExecutorID || !validID(admitted["dispatcher_incarnation"].(string)) || !validID(admitted["session_id"].(string)) {
				t.Fatalf("missing control binding: %+v", admitted)
			}
			if accepted["request_id"] != "unknown" || joined["request_id"] != "unknown" {
				t.Fatal("executor invented HTTP context")
			}
			requests := map[string]int{}
			for _, entry := range dispatcherLogs {
				if entry["msg"] == "HTTP request completed" {
					requests[entry["request_id"].(string)] = int(entry["status"].(float64))
				}
			}
			submitID, cancelID := admitted["request_id"].(string), cancelled["request_id"].(string)
			if validID(submitID) && validID(cancelID) && submitID != cancelID && requests[submitID] == 200 && requests[cancelID] == 204 {
				t.Logf("installed log chain: run=%s executor=%s submit_request=%s cancel_request=%s session=%s", id, e.record.ExecutorID, submitID, cancelID, admitted["session_id"])
				return
			}
		}
		select {
		case <-phase.Done():
			t.Fatal("installed request/run/session log chain incomplete")
		case <-ticker.C:
		}
	}
}
