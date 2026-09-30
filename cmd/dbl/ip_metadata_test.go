// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestNodesFiltersAndLabelsAutomaticLocation(t *testing.T) {
	databases, err := ipmetadata.Open("../../internal/ipmetadata/testdata/asn.mmdb", "../../internal/ipmetadata/testdata/city.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer databases.Close()
	// Synthetic database keys are used only for offline lookup; the HTTP
	// fixture is loopback and no request is sent to the advertised address.
	metadata := func(address string, optOut bool) *wire.IPMetadata {
		return &wire.IPMetadata{
			Observed:       databases.Lookup("127.0.0.1", wire.SourceDispatcherObserved, time.Now().Unix(), optOut),
			Advertised:     databases.Lookup(address, wire.SourceExecutorReported, time.Now().Unix(), optOut),
			LocationOptOut: optOut,
		}
	}
	node := wire.Executor{ID: "fixture", Ready: true, IPMetadata: metadata("8.8.8.8", false)}
	const source = "database:Debuglet-Test-City@1700000000"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /executors", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode([]wire.Executor{node}) })
	fx := newFixture(t, mux)
	code, out, stderr := runCLI(context.Background(), "--endpoint", fx.endpoint(), "nodes", "--asn", "64500", "--country", "CH")
	assertCode(t, code, exitOK, out, stderr)
	if !strings.Contains(out, "AS64500") || !strings.Contains(out, "Fixture city,CH") || !strings.Contains(out, source) {
		t.Fatalf("automatic location: %s", out)
	}
	city, country, operator := "Operator fixture", "DE", wire.SourceOperator
	node.Display.City = wire.LabelledString{Value: &city, Source: &operator}
	node.Display.Country = wire.LabelledString{Value: &country, Source: &operator}
	code, out, stderr = runCLI(context.Background(), "--endpoint", fx.endpoint(), "nodes", "--country", "DE")
	assertCode(t, code, exitOK, out, stderr)
	if !strings.Contains(out, "Operator fixture,DE") || !strings.Contains(out, "operator") || strings.Contains(out, "Fixture city") {
		t.Fatalf("operator display: %s", out)
	}
	code, out, stderr = runCLI(context.Background(), "--endpoint", fx.endpoint(), "--output", "json", "nodes")
	assertCode(t, code, exitOK, out, stderr)
	var listed []wire.Executor
	if err := json.Unmarshal([]byte(out), &listed); err != nil || len(listed) != 1 || listed[0].IPMetadata.Advertised.Location.Value == nil || listed[0].IPMetadata.Advertised.Location.Value.City != "Fixture city" {
		t.Fatalf("automatic comparison absent beside override: %s (%v)", out, err)
	}
	node.IPMetadata = metadata("8.8.8.8", true)
	code, out, stderr = runCLI(context.Background(), "--endpoint", fx.endpoint(), "--output", "json", "nodes")
	assertCode(t, code, exitOK, out, stderr)
	if err := json.Unmarshal([]byte(out), &listed); err != nil || len(listed) != 1 || listed[0].IPMetadata.Advertised.Location.Value != nil || listed[0].IPMetadata.Advertised.Location.Source != nil || listed[0].IPMetadata.Advertised.Location.Reason != "opted_out" || listed[0].Display.Country.Value == nil || *listed[0].Display.Country.Value != country {
		t.Fatalf("opt-out changed operator location or exposed automatic location: %s (%v)", out, err)
	}
	node.Display = wire.ExecutorDisplay{}
	for _, address := range []string{"127.0.0.1", "10.1.2.3", "100.64.0.1"} {
		node.IPMetadata = metadata(address, false)
		code, out, stderr = runCLI(context.Background(), "--endpoint", fx.endpoint(), "nodes")
		assertCode(t, code, exitOK, out, stderr)
		if strings.Contains(out, "Fixture city") || strings.Contains(out, "AS64500") || !strings.Contains(out, "unknown") {
			t.Fatalf("non-global address acquired a location: %s", out)
		}
	}
	before := fx.total()
	for _, args := range [][]string{{"--asn", "0"}, {"--asn", "4294967296"}, {"--country", "ch"}} {
		argv := append([]string{"--endpoint", fx.endpoint(), "nodes"}, args...)
		code, out, stderr = runCLI(context.Background(), argv...)
		if code == exitOK || fx.total() != before {
			t.Fatalf("bad metadata filter reached server: %d %s %s", code, out, stderr)
		}
	}
}
