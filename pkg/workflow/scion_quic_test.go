// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"reflect"
	"strings"
	"testing"
)

func TestSCIONQUICRequirementsAndPinValidation(t *testing.T) {
	client := Workflow{Version: 1, Name: "Pinned SCION QUIC", Entry: "exchange", Nodes: []Node{{ID: "exchange", Block: "scion_quic_exchange", Inputs: map[string]any{"address": "1-ff00:0:111,192.0.2.1:4000", "path_id": "path-a", "certificate_sha256": strings.Repeat("a", 64)}}}}
	p, err := Generate(client)
	if err != nil {
		t.Fatal(err)
	}
	if !p.RequireSCION || p.RequireSCIONListener || !reflect.DeepEqual(p.RequiredHostFunctions, []string{"debuglet_io_v1.scion_quic_exchange"}) || !reflect.DeepEqual(p.Destinations, []string{"192.0.2.1"}) {
		t.Fatal(p)
	}
	client.Nodes[0].Inputs["certificate_sha256"] = "untrusted"
	if ds := Validate(client); len(ds) == 0 {
		t.Fatal("accepted malformed expected pin")
	}
	server := Workflow{Version: 1, Name: "SCION QUIC responder", Entry: "start", Nodes: []Node{{ID: "start", Block: "scion_quic_echo_start"}, {ID: "stop", Block: "scion_quic_echo_stop"}}, Edges: []Edge{edge("control", "start", "next", "stop", "in")}}
	p, err = Generate(server)
	if err != nil {
		t.Fatal(err)
	}
	if !p.RequireSCION || !p.RequireSCIONListener || !reflect.DeepEqual(p.RequiredHostFunctions, []string{"debuglet_io_v1.scion_quic_echo_start", "debuglet_io_v1.scion_quic_echo_stop"}) {
		t.Fatal(p)
	}
	server.Nodes = append(server.Nodes, Node{ID: "raw", Block: "scion_receive"})
	if ds := Validate(server); len(ds) == 0 {
		t.Fatal("accepted raw and QUIC ownership of the same listener")
	}
}
