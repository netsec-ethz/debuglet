// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func scriptedIPMetadata() *wire.IPMetadata {
	address := func(source string) wire.AddressMetadata {
		return wire.AddressMetadata{
			AddressSource: source,
			ASN:           wire.IPLookup[wire.ASInfo]{ObservedAt: 1790598500, Reason: "no_database"},
			Location:      wire.IPLookup[wire.GeoLocation]{ObservedAt: 1790598500, Reason: "no_database"},
		}
	}
	return &wire.IPMetadata{
		Observed: address(wire.SourceDispatcherObserved), Advertised: address(wire.SourceExecutorReported),
		Disagreements: []string{},
	}
}

func TestNodeIPMetadataDocumentKeepsExactFields(t *testing.T) {
	unknown := string(doc(scriptedIPMetadata()).Stdout)
	metadata := scriptedIPMetadata()
	source := "database:Fixture@1790598500"
	metadata.Observed.ASN = wire.IPLookup[wire.ASInfo]{Value: &wire.ASInfo{Number: 64512, Name: "Fixture", Prefix: "203.0.113.0/24"}, Source: &source, ObservedAt: 1790598500}
	metadata.Observed.Location = wire.IPLookup[wire.GeoLocation]{Value: &wire.GeoLocation{Country: "CH", City: "Zurich", Precision: "city"}, Source: &source, ObservedAt: 1790598500}
	known := string(doc(metadata).Stdout)
	field := func(value string) string { return `,"ip_metadata":` + value }
	change := func(value, from, to string) string { return field(strings.Replace(value, from, to, 1)) }
	for _, tc := range []struct {
		name, fields string
		valid        bool
	}{
		{"omitted", "", true},
		{"unknown observations", field(unknown), true},
		{"known observations", field(known), true},
		{"null metadata", field(`null`), false},
		{"wrong metadata type", field(`[]`), false},
		{"duplicate metadata", field(unknown) + field(unknown), false},
		{"case metadata", `,"IP_metadata":` + unknown, false},
		{"missing opt out", change(unknown, `,"location_opt_out":false`, ""), false},
		{"null opt out", change(unknown, `"location_opt_out":false`, `"location_opt_out":null`), false},
		{"case address", change(unknown, `"observed":`, `"Observed":`), false},
		{"unknown address field", change(unknown, `"address_source":`, `"other":true,"address_source":`), false},
		{"null address source", change(unknown, `"address_source":"dispatcher-observed"`, `"address_source":null`), false},
		{"missing lookup reason", change(unknown, `,"reason":"no_database"`, ""), false},
		{"null lookup time", change(unknown, `"observed_at":1790598500`, `"observed_at":null`), false},
		{"case lookup value", change(unknown, `"value":null`, `"Value":null`), false},
		{"duplicate lookup value", change(unknown, `"value":null`, `"value":null,"value":null`), false},
		{"unknown lookup field", change(unknown, `"reason":"no_database"`, `"reason":"no_database","other":true`), false},
		{"wrong lookup source type", change(known, `"source":"`+source+`"`, `"source":1`), false},
		{"null ASN number", change(known, `"number":64512`, `"number":null`), false},
		{"wrong ASN number type", change(known, `"number":64512`, `"number":"64512"`), false},
		{"missing ASN prefix", change(known, `,"prefix":"203.0.113.0/24"`, ""), false},
		{"case ASN name", change(known, `"name":"Fixture"`, `"Name":"Fixture"`), false},
		{"unknown ASN field", change(known, `"number":64512`, `"number":64512,"other":true`), false},
		{"null location city", change(known, `"city":"Zurich"`, `"city":null`), false},
		{"missing location precision", change(known, `,"precision":"city"`, ""), false},
		{"case location country", change(known, `"country":"CH"`, `"Country":"CH"`), false},
		{"unknown location field", change(known, `"country":"CH"`, `"country":"CH","other":true`), false},
		{"null disagreements", change(unknown, `"disagreements":[]`, `"disagreements":null`), false},
		{"null disagreement item", change(unknown, `"disagreements":[]`, `"disagreements":[null]`), false},
		{"wrong disagreement type", change(unknown, `"disagreements":[]`, `"disagreements":[1]`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`[{"id":"` + testExecutor + `","ready":true,"last_seen":1790598500,"version":"test","tesla_delay_sec":2,"tesla_anchor_timestamp_ns":0,"tesla_anchor_key":null,"price_per_bw":0,"currency":"TEST"` + tc.fields + `}]`)
			var nodes []client.Node
			err := decodeCommand(commandResult{Started: true, Stdout: raw}, &nodes)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t error=%v", tc.valid, err)
			}
		})
	}
}
