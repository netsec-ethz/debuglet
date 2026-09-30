// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestRendezvousLifecycleAndCleanup(t *testing.T) {
	const serverID = "d0f74c74-1395-4576-b2bc-441cf692a803"
	const peerID = "b64e8321-17c9-40d4-8774-bfa160eabbd7"
	for _, mode := range []string{"success", "filtered_cleanup", "stale_cleanup", "not_ready", "server_failed", "client_failed", "interrupted", "ambiguous_client"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeServer(t, "")
			var mu sync.Mutex
			submissions, intents := 0, 0
			cancelled := map[string]bool{}
			inspections := map[string]int{}
			endpoint := "127.0.0.1:24001"
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.handle("PUT /payment/intent", func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				intents++
				json.NewEncoder(w).Encode(map[string]any{"method": "TEST", "intent": map[string]string{"transaction_id": "tx", "auth_key": ""}})
			})
			f.handle("PUT /debuglet", func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				submissions++
				if submissions == 2 {
					var body struct {
						Debuglets []Request `json:"debuglets"`
					}
					json.NewDecoder(r.Body).Decode(&body)
					if len(body.Debuglets) != 1 || body.Debuglets[0].Args[0] != endpoint || body.Debuglets[0].Policy.Addresses[0] != "127.0.0.1" {
						t.Error("client lost structured endpoint or least destination permission")
					}
					if mode == "ambiguous_client" {
						w.WriteHeader(500)
						json.NewEncoder(w).Encode(map[string]string{"code": CodeInternal, "message": "submission could not be confirmed"})
						return
					}
					json.NewEncoder(w).Encode([]string{peerID})
					return
				}
				json.NewEncoder(w).Encode([]string{serverID})
			})
			f.handle("GET /debuglet/{id}/detail", func(w http.ResponseWriter, r *http.Request) {
				now := time.Now().UTC()
				detail := wire.RunDetail{RunID: serverID, ExecutorID: "server", Outcome: wire.ResultOutcome{State: "RunStateStarted"}}
				if mode == "server_failed" {
					detail.Outcome.State = StateExited
				}
				if mode != "not_ready" {
					detail.Execution = &wire.RunExecution{TimeSource: "dispatcher-observed", StartedObservedAt: &now, TCPListener: &endpoint, ListenerReady: true}
				}
				json.NewEncoder(w).Encode(detail)
			})
			f.handle("GET /debuglet/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
				id := r.PathValue("id")
				zero := int64(0)
				page := LogPage{State: StateExited, Logs: []LogEntry{}, Output: OutputStatus{State: "complete", FinalCursor: &zero}}
				if mode == "client_failed" && id == peerID {
					page.Error = "owned fixture failure"
				}
				if mode == "interrupted" {
					cancel()
					page.State = "RunStateStarted"
					page.Output = OutputStatus{State: "pending"}
				}
				json.NewEncoder(w).Encode(page)
			})
			f.handle("DELETE /debuglet", func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					ID string `json:"debuglet_id"`
				}
				json.NewDecoder(r.Body).Decode(&body)
				mu.Lock()
				cancelled[body.ID] = true
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
			})
			f.handle("GET /debuglet/{id}/recovery", func(w http.ResponseWriter, r *http.Request) {
				id := r.PathValue("id")
				mu.Lock()
				inspections[id]++
				first := inspections[id] == 1
				mu.Unlock()
				ex := "server"
				if id == peerID {
					ex = "peer"
				}
				now := time.Now().UTC()
				current := true
				controlStatus := "current"
				classification := "absent"
				if first && mode == "filtered_cleanup" {
					classification = "filtered"
				}
				if first && mode == "stale_cleanup" {
					current = false
					controlStatus = "unavailable"
				}
				binding := &ControlBinding{DispatcherIncarnation: serverID, SessionID: peerID}
				json.NewEncoder(w).Encode(RecoveryDocument{ID: id, ExecutorID: ex, State: StateExited, CheckedAt: now, OriginalBinding: binding, ControlStatus: controlStatus, Observation: RecoveryObservation{Classification: classification, Observer: &RecoveryObserver{ExecutorID: ex, Binding: *binding}, ReceivedAt: &now, CurrentAtCheck: &current}})
			})
			server := Request{ExecutorID: "server", Wasm: []byte{1}, Policy: Policy{TimeoutMS: 1000, ListenTCP: true}}
			peer := Request{ExecutorID: "peer", Wasm: []byte{1}, Args: []string{ServerEndpoint}, Policy: Policy{TimeoutMS: 1000}}
			result, err := f.client(t, Options{}).RendezvousTEST(ctx, server, peer, RendezvousOptions{ReadinessTimeout: 20 * time.Millisecond, Timeout: time.Second})
			wantSuccess := mode == "success" || mode == "filtered_cleanup" || mode == "stale_cleanup"
			if wantSuccess && err != nil {
				t.Fatal(err)
			}
			if !wantSuccess && err == nil {
				t.Fatal("failure incorrectly succeeded")
			}
			mu.Lock()
			defer mu.Unlock()
			want := 2
			if mode == "not_ready" || mode == "server_failed" {
				want = 1
			}
			if submissions != want || intents != want {
				t.Fatalf("unexpected replay %d/%d", submissions, intents)
			}
			if !cancelled[serverID] || result.Server.Cleanup != "confirmed_absent" {
				t.Fatalf("server not cleaned: %+v", result)
			}
			if want == 2 && mode != "ambiguous_client" && (!cancelled[peerID] || result.Client.Cleanup != "confirmed_absent") {
				t.Fatalf("client not cleaned: %+v", result)
			}
			if mode == "ambiguous_client" && (result.Client.ID != "" || !strings.Contains(err.Error(), "500")) {
				t.Fatal("uncertain submission fabricated a run")
			}
			if (mode == "filtered_cleanup" || mode == "stale_cleanup") && (inspections[serverID] < 2 || inspections[peerID] < 2) {
				t.Fatal("cleanup accepted filtered or historical observation as current absence")
			}
		})
	}
}
