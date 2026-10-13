//go:build linux && roles_integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package roles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

type deliverySettings struct {
	DeadlineMS   int    `json:"deadline_ms"`
	RetryMS      int    `json:"retry_ms"`
	RepairMS     int    `json:"repair_ms"`
	PayloadBytes int    `json:"payload_bytes"`
	UpdateID     string `json:"update_id"`
	BlockedFrom  int    `json:"blocked_from"`
	BlockedTo    int    `json:"blocked_to"`
}

type deliveryObservation struct {
	Schema            string           `json:"schema"`
	Type              string           `json:"type"`
	Event             string           `json:"event"`
	Algorithm         string           `json:"algorithm"`
	Role              int              `json:"role"`
	Participants      int              `json:"participants"`
	ExperimentID      string           `json:"experiment_id"`
	RunID             string           `json:"run_id"`
	Hash              string           `json:"update_sha256"`
	PeerRole          int              `json:"peer_role"`
	MessageKind       string           `json:"message_kind"`
	Bytes             int              `json:"bytes"`
	Config            deliverySettings `json:"config"`
	Outcome           string           `json:"outcome"`
	Verified          bool             `json:"verified"`
	CompletionMS      *float64         `json:"completion_ms"`
	FinishedMS        float64          `json:"finished_ms"`
	AckedRoles        []int            `json:"acked_roles"`
	MissingRoles      []int            `json:"missing_ack_roles"`
	SentBytes         int              `json:"sent_bytes"`
	ReceivedBytes     int              `json:"received_bytes"`
	SendErrors        int              `json:"send_errors"`
	SimulatedFailures int              `json:"simulated_failures"`
}

// TestInstalledDeliveryExperiment uses five independent installed executors for
// direct delivery, relay delivery and two declared application-level failures.
func TestInstalledDeliveryExperiment(t *testing.T) {
	ctx, assets, work, launch := installedRendezvous(t)
	wasmPath := os.Getenv("DEBUGLET_DELIVERY_WASM")
	if !filepath.IsAbs(wasmPath) || os.Getenv("DEBUGLET_DELIVERY_SOURCE_SHA") != assets.Manifest.SourceSHA {
		t.Fatal("absolute delivery WASM path and matching installed source revision required")
	}
	wasm, err := os.ReadFile(wasmPath)
	if err != nil || len(wasm) == 0 {
		t.Fatalf("delivery WASM: %v", err)
	}
	t.Logf("installed source=%s delivery SHA256=%x", assets.Manifest.SourceSHA, sha256.Sum256(wasm))
	d := launch("dispatcher", assets.Dispatcher, storagecheck.Dispatcher, dispatcherconfig.DispatcherConfig{
		Admission: dispatcherconfig.DefaultAdmissionConfig(), Attribution: dispatcherconfig.DefaultAttributionConfig(),
		Server: dispatcherconfig.ServerConfig{BindHost: "127.0.0.1", LocalDevelopment: true, Version: assets.Manifest.Version},
		TLS:    dispatcherconfig.TLSConfig{Disable: true}, Sui: dispatcherconfig.SuiConfig{Disabled: true},
		Scheduler: dispatcherconfig.SchedulerConfig{ExecutorTimeout: 10, SchedulerGranularityMs: 100}, Output: dispatcherconfig.DefaultOutputConfig(),
		Database: dispatcherconfig.DatabaseConfig{Path: filepath.Join(work, "dispatcher", "state.sqlite")}, Logging: dispatcherconfig.LoggingConfig{LogLevel: "info", JSONLogs: true},
	})
	c := sdk(t, "http://"+d.HTTPAddr)
	// Hold every candidate port while choosing the others so endpoints differ.
	listeners := make([]net.Listener, 5)
	for i := range listeners {
		listeners[i], err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listeners[i].Close() })
	}
	participants := make([]client.ExperimentRun, len(listeners))
	for i, listener := range listeners {
		id, name := uuid.NewString(), fmt.Sprintf("executor-%d", i)
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		local := true
		launch(name, assets.Executor, storagecheck.Executor, executorconfig.ExecutorConfig{
			Identity:   executorconfig.IdentityConfig{ExecutorID: id, Version: assets.Manifest.Version},
			Dispatcher: executorconfig.DispatcherConfig{Addr: d.GRPCAddr, YamuxAddr: d.HTTPAddr}, TLS: executorconfig.TLSConfig{Disable: true},
			Resources: executorconfig.ResourcesConfig{Capacity: 10_000_000, MaxDebuglets: 4}, Tesla: executorconfig.TeslaConfig{Delay: 1, ChainLength: 300},
			Network:  executorconfig.NetworkConfig{PublicHost: "127.0.0.1", PublicPorts: strconv.Itoa(port), PacketCounter: "fallback", DisableSCIONEnvironment: true, Policy: executorconfig.PolicyConfig{LocalTargets: &local}},
			Database: executorconfig.DatabaseConfig{Path: filepath.Join(work, name, "state.sqlite")}, Logging: executorconfig.LoggingConfig{LogLevel: "info", JSONLogs: true}, Pricing: executorconfig.PricingConfig{Currency: "TEST", PricePerBwS: 1},
		})
		participants[i] = client.ExperimentRun{OrderID: int64(i), ExecutorID: id, WASMPath: wasmPath,
			Policy: client.Policy{FloorBW: 100_000, CeilBW: 1_000_000, TimeoutMS: 45_000, Addresses: []string{"127.0.0.1"}, ListenTCP: true}}
	}
	for {
		nodes, err := c.Nodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ready := 0
		for _, node := range nodes {
			if node.Ready {
				ready++
			}
		}
		if ready == len(participants) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("five executors did not become ready:", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	for _, scenario := range []struct {
		name, algorithm string
		from, to        int
	}{
		{"direct", "direct", -1, -1}, {"relay", "relay", -1, -1},
		{"direct_partial", "direct", 0, 4}, {"relay_repair", "relay", 1, 3},
	} {
		if !t.Run(scenario.name, func(t *testing.T) {
			settings := deliverySettings{5000, 250, 750, 512, "installed-delivery", scenario.from, scenario.to}
			for role := range participants {
				participants[role].Args = []string{"-algorithm=" + scenario.algorithm, "-role=" + strconv.Itoa(role), "-participants=5", "-deadline-ms=5000", "-retry-ms=250", "-repair-ms=750", "-payload-bytes=512", "-update-id=" + settings.UpdateID, "-blocked-from=" + strconv.Itoa(scenario.from), "-blocked-to=" + strconv.Itoa(scenario.to)}
			}
			submission, err := c.SubmitExperimentTEST(ctx, client.ExperimentDefinition{Participants: participants})
			if err != nil {
				t.Fatal("submit delivery group:", err)
			}
			if len(submission.Participants) != 5 {
				t.Fatal("incomplete submission receipt")
			}
			evidence := filepath.Join(os.Getenv("DEBUGLET_ROLE_EVIDENCE_DIR"), "delivery-"+submission.ExperimentID)
			if err := os.Mkdir(evidence, 0700); err != nil {
				t.Fatal(err)
			}
			var summaries [5]deliveryObservation
			var events [5][]deliveryObservation
			payload := make([]byte, settings.PayloadBytes)
			for i := range payload {
				payload[i] = byte((i*31 + 17) % 251)
			}
			hash := fmt.Sprintf("%x", sha256.Sum256(payload))
			for role, participant := range submission.Participants {
				if !validID(participant.RunID) {
					t.Fatal("missing admitted run identity")
				}
				output := installedDeliveryOutput(t, ctx, c, participant.RunID, filepath.Join(evidence, fmt.Sprintf("role-%d.jsonl", role)))
				decoder := json.NewDecoder(bytes.NewReader(output))
				var sent, received, sendErrors, simulated, ready, started int
				for {
					var row deliveryObservation
					if err := decoder.Decode(&row); err == io.EOF {
						break
					} else if err != nil {
						t.Fatalf("role %d output=%s: %v", role, output, err)
					}
					if summaries[role].Type != "" {
						t.Fatal("output after final summary")
					}
					if row.Schema != "debuglet.delivery.v1" || row.Role != role || row.Participants != 5 || row.Algorithm != scenario.algorithm || row.ExperimentID != submission.ExperimentID || row.RunID != participant.RunID || row.Hash != hash {
						t.Fatalf("role %d output identity: %+v", role, row)
					}
					switch row.Type {
					case "summary":
						summaries[role] = row
					case "event":
						events[role] = append(events[role], row)
						if row.Bytes < 0 {
							t.Fatal("negative traffic count")
						}
						switch row.Event {
						case "send":
							sent += row.Bytes
						case "send_error":
							sent += row.Bytes
							sendErrors++
						case "receive", "invalid_message":
							received += row.Bytes
						case "ready":
							ready++
						case "start":
							started++
						case "simulated_failure":
							simulated++
							if role != scenario.from || row.PeerRole != scenario.to || row.Bytes != 0 {
								t.Fatal("simulated failure changed its declared edge or charged traffic")
							}
						}
					default:
						t.Fatalf("unexpected output type %q", row.Type)
					}
				}
				summary := summaries[role]
				if summary.Type != "summary" || summary.Config != settings || ready != 1 || started != 1 || summary.SentBytes != sent || summary.ReceivedBytes != received || summary.SendErrors != sendErrors || summary.SimulatedFailures != simulated {
					t.Fatalf("role %d incomplete output or mismatched traffic totals: %+v", role, summary)
				}
				partial := scenario.name == "direct_partial" && (role == 0 || role == 4)
				wantOutcome, wantExit := "complete", int32(0)
				if partial {
					wantOutcome, wantExit = "deadline", 1
				}
				if summary.Outcome != wantOutcome || summary.Verified != !(scenario.name == "direct_partial" && role == 4) || summary.FinishedMS < 5000 {
					t.Fatalf("role %d outcome: %+v", role, summary)
				}
				detail, err := c.RunDetail(ctx, participant.RunID)
				if err != nil || detail.Execution == nil || detail.Execution.ReportedExitCode == nil || *detail.Execution.ReportedExitCode != wantExit || detail.Outcome.State != client.StateExited {
					t.Fatalf("role %d terminal report: %+v %v", role, detail.Execution, err)
				}
				t.Logf("%s role=%d run=%s outcome=%s verified=%t sent=%d received=%d simulated=%d", scenario.name, role, participant.RunID, summary.Outcome, summary.Verified, sent, received, simulated)
			}
			origin := summaries[0]
			if scenario.name == "direct_partial" {
				if !slices.Equal(origin.AckedRoles, []int{1, 2, 3}) || !slices.Equal(origin.MissingRoles, []int{4}) || origin.CompletionMS != nil || origin.SimulatedFailures == 0 {
					t.Fatalf("partial delivery was not retained accurately: %+v", origin)
				}
			} else if !slices.Equal(origin.AckedRoles, []int{1, 2, 3, 4}) || len(origin.MissingRoles) != 0 || origin.CompletionMS == nil || *origin.CompletionMS < 0 || *origin.CompletionMS > 5000 {
				t.Fatalf("origin did not acknowledge all four recipients: %+v", origin)
			}
			if scenario.name == "relay_repair" {
				repaired := false
				for helper := 2; helper < 5; helper++ {
					if helper == 3 {
						continue
					}
					requested, sent, received := false, false, false
					for _, event := range events[helper] {
						if event.Event == "repair" && event.PeerRole == 3 {
							requested = true
						}
						if requested && event.Event == "send" && event.MessageKind == "data" && event.PeerRole == 3 && event.Bytes > 0 {
							sent = true
						}
					}
					for _, event := range events[3] {
						if event.Event == "receive" && event.MessageKind == "data" && event.PeerRole == helper && event.Bytes > 0 {
							received = true
						}
					}
					repaired = repaired || requested && sent && received
				}
				if !repaired || summaries[1].SimulatedFailures == 0 {
					t.Fatal("missing successful helper repair of the simulated 1-to-3 failure")
				}
			}
			group, err := c.ExportExperiment(ctx, submission)
			if err != nil || len(group.Results) != 5 {
				t.Fatalf("complete grouped export: %d results, %v", len(group.Results), err)
			}
		}) {
			return
		}
	}
}

func installedDeliveryOutput(t *testing.T, ctx context.Context, c *client.Client, id, path string) (output []byte) {
	t.Helper()
	defer func() {
		if err := os.WriteFile(path, output, 0600); err != nil {
			t.Error("save delivery output:", err)
		}
	}()
	var after int64
	for {
		page, err := c.Logs(ctx, id, client.LogOptions{After: after, Limit: 100})
		if err != nil {
			t.Fatal("read delivery output:", err)
		}
		for _, entry := range page.Logs {
			if entry.ID <= after {
				t.Fatal("output cursor did not advance")
			}
			output = append(output, entry.Output...)
			after = entry.ID
		}
		if page.After != after || len(output) > 256<<10 || page.Output.State == "truncated" {
			t.Fatalf("invalid delivery output page: %+v", page)
		}
		if page.State == client.StateExited && !page.HasMore && page.Output.State == "complete" && page.Output.FinalCursor != nil {
			return output
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for complete output from %s: %v; terminal error=%q", id, ctx.Err(), page.Error)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
