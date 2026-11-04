// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func scionCatalog() []Block {
	status := func(ports ...Port) []Port {
		return append([]Port{output("ok", "boolean"), output("error", "string")}, ports...)
	}
	return []Block{
		{"scion_paths", "Discover SCION paths", "Network", "Discover paths from this executor to a SCION UDP endpoint (ISD-AS,IP:port). Each path has an opaque id, interfaces, hop_count, mtu and expires_ms. Discovery is not proof of delivery. Use ordinary list, field and filter blocks to inspect paths.", false,
			[]Port{input("address", "string"), optional("timeout_ms", "number", float64(2000))},
			status(output("paths", "any")), []string{"next"}},
		{"scion_select_path", "Select SCION path", "Network", "Pin a discovered path by its stable id for this endpoint. Returns the current path descriptor, or an error if it disappeared. Never silently substitutes another path. Pass path_id explicitly to SCION UDP exchange.", false,
			[]Port{input("address", "string"), input("path_id", "string"), optional("timeout_ms", "number", float64(2000))},
			status(output("path", "object"), output("path_id", "string")), []string{"next"}},
		{"scion_udp_exchange", "SCION UDP exchange", "Network", "Send one datagram on an explicitly chosen path and receive one reply. path_id is the actual outgoing path, not a claim about the return path. Duration covers the exchange; it is not one-way delay. No fallback, TCP or TESLA tagging. Requires a reachable SCION UDP responder.", false,
			[]Port{input("address", "string"), input("path_id", "string"), optional("payload", "string", ""), optional("encoding", "string", "text"), optional("max_bytes", "number", float64(4096)), optional("timeout_ms", "number", float64(2000))},
			status(output("response", "string"), output("response_base64", "string"), output("sender", "string"), output("path_id", "string"), output("duration_ms", "number"), output("received_bytes", "number"), output("complete", "boolean"), output("truncated", "boolean")), []string{"next"}},
		{"scion_listener_address", "SCION listener address", "Network", "Read this run's admitted SCION UDP endpoint. In a coordinated experiment, send this address to the probing participant using Send message. The control messages still use ordinary TCP.", false,
			[]Port{}, status(output("address", "string")), []string{"next"}},
		{"scion_receive", "Receive SCION UDP", "Network", "Wait for one admitted datagram on this run's SCION listener. Pass sender to Reply SCION UDP. payload_base64 preserves exact bytes; a truncated datagram is not a complete success. Requires a SCION listener.", false,
			[]Port{optional("max_bytes", "number", float64(4096)), optional("encoding", "string", "text"), optional("timeout_ms", "number", float64(2000))},
			status(output("payload", "string"), output("payload_base64", "string"), output("sender", "string"), output("received_at_ms", "number"), output("received_bytes", "number"), output("truncated", "boolean")), []string{"next"}},
		{"scion_reply", "Reply SCION UDP", "Network", "Reply from this run's SCION listener to the exact sender of its most recently received admitted datagram. Wire sender from Receive SCION UDP. Payload encoding is text or base64, up to 4096 bytes.", false,
			[]Port{input("sender", "string"), optional("payload", "string", ""), optional("encoding", "string", "text"), optional("timeout_ms", "number", float64(2000))},
			status(output("bytes_sent", "number")), []string{"next"}},
	}
}

func scionHostFunction(block string) string {
	return map[string]string{
		"scion_paths": "scion_paths", "scion_select_path": "scion_select_path",
		"scion_udp_exchange": "scion_exchange", "scion_listener_address": "scion_listener_address",
		"scion_receive": "scion_receive", "scion_reply": "scion_reply",
	}[block]
}
