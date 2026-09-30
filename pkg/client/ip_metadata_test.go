// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func metadataFixture(t *testing.T) *wire.IPMetadata {
	t.Helper()
	db, err := ipmetadata.Open("../../internal/ipmetadata/testdata/asn.mmdb", "../../internal/ipmetadata/testdata/city.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	return &wire.IPMetadata{Observed: db.Lookup("8.8.8.8", wire.SourceDispatcherObserved, 1700000123, false), Advertised: db.Lookup("", wire.SourceExecutorReported, 1700000123, false), Disagreements: []string{}}
}

func TestMetadataFiltersAndPortableResults(t *testing.T) {
	m := metadataFixture(t)
	country, source := "CH", *m.Observed.Location.Source
	nodes := []Node{{ID: "unknown", Ready: true}, {ID: "match", Ready: true, IPMetadata: m, Display: wire.ExecutorDisplay{Country: wire.LabelledString{Value: &country, Source: &source}}}}
	f := newFakeServer(t, "")
	f.handle("GET /executors", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(nodes) })
	c := f.client(t, Options{})
	for _, filter := range []ExecutorFilter{{ASN: 64500}, {Country: "CH"}, {ASN: 64500, Country: "CH"}} {
		got, err := c.SelectExecutor(t.Context(), "", filter)
		if err != nil || got.ID != "match" {
			t.Fatalf("%+v: %+v %v", filter, got, err)
		}
	}
	for _, filter := range []ExecutorFilter{{ASN: 1}, {Country: "DE"}} {
		if got, err := c.DiscoverExecutors(t.Context(), filter); err != nil || len(got) != 0 {
			t.Fatalf("nonmatch: %+v %v", got, err)
		}
	}
	if _, err := c.DiscoverExecutors(t.Context(), ExecutorFilter{Country: "ch"}); err == nil {
		t.Fatal("invalid country accepted")
	}
	data, err := os.ReadFile("testdata/results/v1.1.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ReadResult(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	doc.Provenance.VantagePoint.IPMetadata = m
	doc.Provenance.VantagePoint.Display.Country = wire.LabelledString{Value: &country, Source: &source}
	var output bytes.Buffer
	if err := json.NewEncoder(&output).Encode(doc); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResult(&output)
	if err != nil || got.Provenance.VantagePoint.IPMetadata.Observed.ASN.Value.Number != 64500 {
		t.Fatalf("portable metadata: %+v %v", got, err)
	}
	m.LocationOptOut = true
	if validIPMetadata(m) {
		t.Fatal("opt-out accepted published location")
	}
}
