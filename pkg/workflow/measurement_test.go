// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGeneratedCollectionAccumulatesAcrossRepeat(t *testing.T) {
	if testing.Short() {
		t.Skip("generated program compilation")
	}
	w := Workflow{Version: 1, Name: "Collect iterations", Entry: "start", Nodes: []Node{
		{ID: "start", Block: "start_timer"},
		{ID: "new", Block: "create_collection"},
		{ID: "repeat", Block: "repeat", Inputs: map[string]any{"count": float64(3)}},
		{ID: "collect", Block: "collect"},
		{ID: "read", Block: "read_collection"},
		{ID: "mean", Block: "mean"},
		{ID: "emit", Block: "emit", Inputs: map[string]any{"name": "mean"}},
		{ID: "elapsed", Block: "elapsed"},
		{ID: "reset", Block: "reset_collection"},
		{ID: "empty", Block: "read_collection"},
	}, Edges: []Edge{
		edge("control", "start", "next", "new", "in"), edge("control", "new", "next", "repeat", "in"),
		edge("control", "repeat", "body", "collect", "in"), edge("control", "repeat", "done", "read", "in"),
		edge("data", "new", "collection", "collect", "collection"), edge("data", "repeat", "iteration", "collect", "value"),
		edge("data", "new", "collection", "read", "collection"), edge("data", "read", "values", "mean", "values"),
		edge("control", "read", "next", "emit", "in"), edge("data", "mean", "value", "emit", "value"),
		edge("control", "emit", "next", "elapsed", "in"), edge("data", "start", "timer", "elapsed", "timer"),
		edge("control", "elapsed", "next", "reset", "in"), edge("data", "new", "collection", "reset", "collection"),
		edge("control", "reset", "next", "empty", "in"), edge("data", "new", "collection", "empty", "collection"),
	}}
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "main.go")
	if err = os.WriteFile(source, []byte(p.Source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", source)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated program: %v\n%s", err, raw)
	}
	events := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e struct {
			Node    string         `json:"node_id"`
			Outputs map[string]any `json:"outputs"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		events[e.Node] = e.Outputs
	}
	if !reflect.DeepEqual(events["read"]["values"], []any{float64(1), float64(2), float64(3)}) || events["emit"]["value"] != float64(2) {
		t.Fatal("repeat samples were lost:", events)
	}
	if events["elapsed"]["duration_ms"].(float64) < 0 || !reflect.DeepEqual(events["empty"]["values"], []any{}) {
		t.Fatal("invalid timer or reset outcome:", events)
	}
}

func TestMeasurementMetadata(t *testing.T) {
	w := Workflow{Version: 1, Name: "Network requirements", Entry: "dns", Nodes: []Node{
		{ID: "dns", Block: "dns_query", Inputs: map[string]any{"resolver": "192.0.2.53:53", "name": "example.test"}},
		{ID: "udp", Block: "udp_exchange", Inputs: map[string]any{"target": "192.0.2.1:9999"}},
		{ID: "tcp", Block: "tcp_exchange", Inputs: map[string]any{"target": "192.0.2.1:8888"}},
		{ID: "tls", Block: "tls_inspect", Inputs: map[string]any{"target": "example.test:443"}},
		{ID: "hop", Block: "hop_probe", Inputs: map[string]any{"target": "192.0.2.3"}},
		{ID: "listen", Block: "udp_listener"},
		{ID: "receive", Block: "udp_receive"},
		{ID: "reply", Block: "udp_reply", Inputs: map[string]any{"destination": "192.0.2.4:4000", "payload": "ok"}},
	}}
	p, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if !p.RequireUDPListener || !p.RequireICMP || !reflect.DeepEqual(p.Destinations, []string{"192.0.2.1", "192.0.2.3", "192.0.2.4", "192.0.2.53", "example.test"}) {
		t.Fatalf("wrong network requirements: %+v", p)
	}
	want := []string{"debuglet_io_v1.hop_probe", "debuglet_io_v1.receive_udp", "debuglet_io_v1.reply_udp", "debuglet_io_v1.tls_inspect"}
	if !reflect.DeepEqual(p.RequiredHostFunctions, want) {
		t.Fatal(p.RequiredHostFunctions)
	}
	legacy, err := Generate(sampleWorkflow())
	if err != nil || legacy.RequireUDPListener || len(legacy.RequiredHostFunctions) != 0 {
		t.Fatal("ordinary workflow gained host requirements:", legacy, err)
	}
}

func TestMeasurementLiteralValidation(t *testing.T) {
	for _, n := range []Node{
		{ID: "bad", Block: "dns_query", Inputs: map[string]any{"resolver": "resolver.test:53", "name": "example.test"}},
		{ID: "bad", Block: "dns_query", Inputs: map[string]any{"resolver": "192.0.2.53:53", "name": "example.test", "transport": "quic"}},
		{ID: "bad", Block: "hop_probe", Inputs: map[string]any{"target": "192.0.2.1", "ttl": float64(256)}},
		{ID: "bad", Block: "udp_exchange", Inputs: map[string]any{"target": "192.0.2.1:1234", "max_bytes": float64(8192)}},
		{ID: "bad", Block: "udp_receive", Inputs: map[string]any{"encoding": "hex"}},
		{ID: "bad", Block: "tcp_exchange", Inputs: map[string]any{"target": "192.0.2.1:1234", "delimiter": ""}},
	} {
		t.Run(n.Block, func(t *testing.T) {
			w := Workflow{Version: 1, Name: "Invalid input", Entry: n.ID, Nodes: []Node{n}}
			if ds := Validate(w); len(ds) == 0 {
				t.Fatal("accepted invalid literal")
			}
		})
	}
	w := Workflow{Version: 1, Name: "Missing experiment", Entry: "barrier", Nodes: []Node{{ID: "barrier", Block: "phase_barrier", Inputs: map[string]any{"phase": "ready"}}}}
	if _, err := Generate(w); err == nil || !strings.Contains(err.Error(), "whole experiment") {
		t.Fatalf("standalone barrier: %v", err)
	}
}
