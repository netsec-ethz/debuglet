// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"reflect"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSConvenienceAnswersPreserveOrderAndRawRecords(t *testing.T) {
	query, response := dnsFixture(t)
	name, _ := dnsmessage.NewName("ns.example.test.")
	alias, _ := dnsmessage.NewName("service.example.test.")
	header := dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}
	response.Answers = append(response.Answers,
		dnsmessage.Resource{Header: header, Body: &dnsmessage.NSResource{NS: name}},
		dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}},
		response.Answers[0],
		dnsmessage.Resource{Header: header, Body: &dnsmessage.CNAMEResource{CNAME: alias}},
		dnsmessage.Resource{Header: header, Body: &dnsmessage.PTRResource{PTR: name}},
		dnsmessage.Resource{Header: header, Body: &dnsmessage.MXResource{Pref: 10, MX: name}},
	)
	response.Additionals = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 99}}}}
	wire, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, err := networkDNSResponse(wire, query)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out["addresses"], []any{"192.0.2.9", "2001:db8::1"}) || !reflect.DeepEqual(out["names"], []any{"ns.example.test.", "service.example.test."}) {
		t.Fatalf("convenience answers = %v, %v", out["addresses"], out["names"])
	}
	if len(out["answers"].([]any)) != 7 || len(out["additionals"].([]any)) != 1 {
		t.Fatalf("raw records changed: %v", out)
	}
	if err := Check(out, map[string]string{"addresses": "strings", "names": "strings", "nsid_base64": "string", "nsid_present": "boolean"}); err != nil {
		t.Fatal(err)
	}
}

func TestDNSNSIDDistinguishesAbsentEmptyAndBinary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []dnsmessage.Option
		value   string
		present bool
	}{
		{name: "absent", options: []dnsmessage.Option{{Code: 12, Data: []byte{0}}}},
		{name: "empty", options: []dnsmessage.Option{{Code: 3}}, present: true},
		{name: "binary", options: []dnsmessage.Option{{Code: 3, Data: []byte{255, 0, 128}}}, value: "/wCA", present: true},
		{name: "first", options: []dnsmessage.Option{{Code: 3, Data: []byte{1}}, {Code: 3, Data: []byte{2}}}, value: "AQ==", present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query, response := dnsFixture(t)
			root, _ := dnsmessage.NewName(".")
			response.Answers = nil
			response.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: root, Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{Options: tc.options}}}
			wire, err := response.Pack()
			if err != nil {
				t.Fatal(err)
			}
			out, err := networkDNSResponse(wire, query)
			if err != nil || out["nsid_base64"] != tc.value || out["nsid_present"] != tc.present {
				t.Fatalf("NSID = %v, error = %v", out, err)
			}
			if !reflect.DeepEqual(out["addresses"], []any{}) || !reflect.DeepEqual(out["names"], []any{}) {
				t.Fatalf("empty answers = %v, %v", out["addresses"], out["names"])
			}
		})
	}
}
