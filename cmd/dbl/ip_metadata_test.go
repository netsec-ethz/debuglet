// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestNodesFiltersAndLabelsAutomaticLocation(t *testing.T) {
	source := "database:Fixture@1700000000"
	node := wire.Executor{ID: "fixture", Ready: true, IPMetadata: &wire.IPMetadata{Observed: wire.AddressMetadata{ASN: wire.IPLookup[wire.ASInfo]{Value: &wire.ASInfo{Number: 64500, Name: "Synthetic network", Prefix: "8.0.0.0/8"}, Source: &source}, Location: wire.IPLookup[wire.GeoLocation]{Value: &wire.GeoLocation{Country: "CH", City: "Fixture city", Precision: "city"}, Source: &source}}}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /executors", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode([]wire.Executor{node}) })
	fx := newFixture(t, mux)
	code, out, err := runCLI(context.Background(), "--endpoint", fx.endpoint(), "nodes", "--asn", "64500", "--country", "CH")
	assertCode(t, code, exitOK, out, err)
	if !strings.Contains(out, "AS64500") || !strings.Contains(out, "Fixture city,CH") || !strings.Contains(out, source) {
		t.Fatalf("automatic location: %s", out)
	}
	before := fx.total()
	for _, args := range [][]string{{"--asn", "0"}, {"--asn", "4294967296"}, {"--country", "ch"}} {
		argv := append([]string{"--endpoint", fx.endpoint(), "nodes"}, args...)
		code, out, err = runCLI(context.Background(), argv...)
		if code == exitOK || fx.total() != before {
			t.Fatalf("bad metadata filter reached server: %d %s %s", code, out, err)
		}
	}
}
