// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSInvalidInputsDoNotDial(t *testing.T) {
	for _, patch := range []map[string]any{
		{"resolver": "resolver.example:53"}, {"resolver": "192.0.2.1:0"}, {"resolver": "192.0.2.1"},
		{"name": ""}, {"name": strings.Repeat("a", 64) + ".test"}, {"name": "example..test"},
		{"transport": "https"}, {"record_type": "nope"}, {"record_type": "TYPE65536"}, {"record_type": "TYPE0"},
		{"timeout_ms": float64(0)}, {"recursion_desired": "yes"}, {"checking_disabled": 1}, {"dnssec_ok": "false"},
	} {
		inputs := map[string]any{"resolver": "192.0.2.53:53", "name": "example.test"}
		for key, value := range patch {
			inputs[key] = value
		}
		if out, err := DNSQuery(inputs); err == nil || out != nil {
			t.Fatalf("accepted %v: %v %v", inputs, out, err)
		}
	}
}

func TestDNSQueryWireAndFlags(t *testing.T) {
	q, err := networkDNSQuery(map[string]any{"resolver": "[2001:db8::53]:53", "name": "_service._tcp.example.test", "record_type": "srv", "transport": "tcp", "recursion_desired": false, "checking_disabled": true, "dnssec_ok": true, "request_nsid": true})
	if err != nil {
		t.Fatal(err)
	}
	var decoded dnsmessage.Message
	if err = decoded.Unpack(q.wire); err != nil {
		t.Fatal(err)
	}
	if decoded.RecursionDesired || !decoded.CheckingDisabled || decoded.Response || decoded.Questions[0].Type != dnsmessage.TypeSRV || decoded.Questions[0].Name.String() != "_service._tcp.example.test." {
		t.Fatalf("query=%+v", decoded)
	}
	if len(decoded.Additionals) != 1 || decoded.Additionals[0].Header.Class != 1232 || decoded.Additionals[0].Header.TTL != 1<<15 {
		t.Fatalf("EDNS=%+v", decoded.Additionals)
	}
	opt := decoded.Additionals[0].Body.(*dnsmessage.OPTResource)
	if len(opt.Options) != 1 || opt.Options[0].Code != 3 || len(opt.Options[0].Data) != 0 {
		t.Fatalf("NSID=%+v", opt)
	}
}

func dnsFixture(t *testing.T) (dnsmessage.Message, dnsmessage.Message) {
	t.Helper()
	q, err := networkDNSQuery(map[string]any{"resolver": "192.0.2.53:53", "name": "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.message.ID, Response: true, Authoritative: true, RecursionDesired: true, RecursionAvailable: true, AuthenticData: true}, Questions: q.message.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 123}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}}}}}
	return q.message, response
}

func TestDNSResponseRecordsAndErrors(t *testing.T) {
	query, response := dnsFixture(t)
	wire, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, err := networkDNSResponse(wire, query)
	if err != nil {
		t.Fatal(err)
	}
	answer := out["answers"].([]any)[0].(map[string]any)
	if answer["name"] != "example.test." || answer["ttl"] != float64(123) || answer["type"] != "A" || answer["data"] != "192.0.2.9" || out["rcode"] != "NOERROR" {
		t.Fatalf("output=%v", out)
	}
	if err = Check(out, map[string]string{"answers": "any", "authorities": "any", "additionals": "any", "flags": "object", "rcode": "string", "truncated": "boolean"}); err != nil {
		t.Fatal(err)
	}
	response.RCode, response.Answers = dnsmessage.RCodeNameError, nil
	wire, _ = response.Pack()
	out, err = networkDNSResponse(wire, query)
	if err != nil || out["rcode"] != "NXDOMAIN" || len(out["answers"].([]any)) != 0 {
		t.Fatalf("NXDOMAIN=%v, %v", out, err)
	}
	response.Truncated = true
	wire, _ = response.Pack()
	out, err = networkDNSResponse(wire, query)
	if err != nil || out["truncated"] != true {
		t.Fatalf("TC=%v, %v", out, err)
	}
}

func TestDNSRejectsMismatchedAndMalformedResponses(t *testing.T) {
	for name, change := range map[string]func(*dnsmessage.Message){
		"id":               func(m *dnsmessage.Message) { m.ID++ },
		"request":          func(m *dnsmessage.Message) { m.Response = false },
		"opcode":           func(m *dnsmessage.Message) { m.OpCode = 1 },
		"missing question": func(m *dnsmessage.Message) { m.Questions = nil },
		"type":             func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA },
		"class":            func(m *dnsmessage.Message) { m.Questions[0].Class = 3 },
		"name":             func(m *dnsmessage.Message) { m.Questions[0].Name, _ = dnsmessage.NewName("other.test.") },
	} {
		t.Run(name, func(t *testing.T) {
			query, response := dnsFixture(t)
			response.Questions = append([]dnsmessage.Question(nil), response.Questions...)
			change(&response)
			wire, err := response.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = networkDNSResponse(wire, query); err == nil {
				t.Fatal("accepted mismatched response")
			}
		})
	}
	query, response := dnsFixture(t)
	wire, _ := response.Pack()
	for _, malformed := range [][]byte{nil, wire[:11], wire[:len(wire)-1], {0, 1, 128, 0, 0, 1, 0, 0, 0, 0, 0, 0, 192, 12, 0, 1, 0, 1}} {
		if _, err := networkDNSResponse(malformed, query); err == nil {
			t.Fatal("accepted malformed response")
		}
	}
}

func TestDNSUnknownRecordsAndNSIDRemainBinarySafe(t *testing.T) {
	query, response := dnsFixture(t)
	response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: 257, Class: 1, TTL: 30}, Body: &dnsmessage.UnknownResource{Type: 257, Data: []byte{0, 255, 1}}})
	root, _ := dnsmessage.NewName(".")
	response.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: root, Type: dnsmessage.TypeOPT, Class: 1232, TTL: 1 << 15}, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 3, Data: []byte{255, 0, 128}}}}}}
	wire, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, err := networkDNSResponse(wire, query)
	if err != nil {
		t.Fatal(err)
	}
	unknown := out["answers"].([]any)[1].(map[string]any)["data"].(map[string]any)["base64"]
	if unknown != base64.StdEncoding.EncodeToString([]byte{0, 255, 1}) {
		t.Fatalf("CAA raw=%v", unknown)
	}
	opt := out["additionals"].([]any)[0].(map[string]any)["data"].(map[string]any)
	nsid := opt["options"].([]any)[0].(map[string]any)["data_base64"]
	if nsid != base64.StdEncoding.EncodeToString([]byte{255, 0, 128}) || opt["dnssec_ok"] != true {
		t.Fatalf("EDNS=%v", opt)
	}
}
