// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func measurementCatalog() []Block {
	return []Block{
		{"dns_query", "DNS query", "Network", "Query a chosen resolver at IP:port over UDP or TCP. ok means a valid response arrived; inspect rcode for DNS success. addresses contains distinct A/AAAA answer values; names contains distinct NS/CNAME/PTR answer values, in response order. nsid_base64 preserves the first EDNS NSID as opaque bytes; nsid_present distinguishes absence from an empty identifier. NSID does not prove physical server identity. Full records and TTLs remain available. No automatic retry or TCP fallback.", false,
			[]Port{input("resolver", "string"), input("name", "string"), optional("record_type", "string", "A"), optional("transport", "string", "udp"), optional("recursion_desired", "boolean", true), optional("checking_disabled", "boolean", false), optional("dnssec_ok", "boolean", false), optional("request_nsid", "boolean", false), optional("timeout_ms", "number", float64(2000))},
			[]Port{output("ok", "boolean"), output("error", "string"), output("rcode", "string"), output("answers", "any"), output("addresses", "strings"), output("names", "strings"), output("authorities", "any"), output("additionals", "any"), output("nsid_base64", "string"), output("nsid_present", "boolean"), output("flags", "object"), output("response_base64", "string"), output("duration_ms", "number"), output("truncated", "boolean")}, []string{"next"}},
		{"udp_exchange", "UDP exchange", "Network", "Send one datagram to host:port and wait for one response. Payload encoding is text or base64; response_base64 preserves exact bytes. Maximum response is 8191 bytes; larger replies are marked truncated.", false,
			[]Port{input("target", "string"), optional("payload", "string", ""), optional("encoding", "string", "text"), optional("max_bytes", "number", float64(4096)), optional("timeout_ms", "number", float64(2000))},
			exchangeOutputs(), []string{"next"}},
		{"tcp_exchange", "TCP exchange", "Network", "Connect, send a payload, then read until a delimiter, byte count, or EOF. One timeout covers the exchange. response_base64 preserves exact bytes; complete distinguishes the requested ending from a size limit.", false,
			[]Port{input("target", "string"), optional("payload", "string", ""), optional("encoding", "string", "text"), optional("read_until", "string", "delimiter"), optional("delimiter", "string", "\n"), optional("max_bytes", "number", float64(4096)), optional("timeout_ms", "number", float64(2000))},
			exchangeOutputs(), []string{"next"}},
		{"tls_inspect", "TLS handshake", "Network", "Connect with normal certificate verification and inspect the negotiated TLS session and peer certificates. Duration includes resolution, connection and handshake; it is not handshake-only timing. Requires an updated executor.", false,
			[]Port{input("target", "string"), optional("timeout_ms", "number", float64(2000))},
			[]Port{output("ok", "boolean"), output("error", "string"), output("duration_ms", "number"), output("tls_version", "string"), output("cipher", "string"), output("alpn", "string"), output("server_name", "string"), output("peer_address", "string"), output("certificates", "any"), output("verified", "boolean")}, []string{"next"}},
		{"hop_probe", "Hop probe", "Network", "Send one IPv4 ICMP echo probe with a chosen TTL (1–255). Reports a correlated router or destination response. Requires ICMP and an updated executor. Repeat with increasing TTLs to inspect a route.", false,
			[]Port{input("target", "string"), optional("ttl", "number", float64(1)), optional("timeout_ms", "number", float64(2000))},
			[]Port{output("ok", "boolean"), output("error", "string"), output("duration_ms", "number"), output("reply_address", "string"), output("icmp_type", "number"), output("icmp_code", "number"), output("reached", "boolean")}, []string{"next"}},
		{"udp_listener", "UDP listener address", "Network", "Read this run's admitted public UDP endpoint before receiving a packet. Enable a UDP listener when submitting the program.", false,
			[]Port{}, []Port{output("address", "string")}, []string{"next"}},
		{"udp_receive", "Receive UDP", "Network", "Wait for one datagram on this run's admitted UDP listener. source can feed Reply UDP. payload uses text or base64; payload_base64 always preserves the received bytes. Requires an updated executor.", false,
			[]Port{optional("timeout_ms", "number", float64(2000)), optional("max_bytes", "number", float64(8192)), optional("encoding", "string", "text")},
			[]Port{output("ok", "boolean"), output("error", "string"), output("source", "string"), output("payload", "string"), output("payload_base64", "string"), output("bytes", "number"), output("truncated", "boolean"), output("duration_ms", "number")}, []string{"next"}},
		{"udp_reply", "Reply UDP", "Network", "Reply to the last successfully received datagram from this run's UDP listener, subject to current outbound policy. Connect Receive UDP's source to destination. Payload encoding is text or base64. Requires an updated executor.", false,
			[]Port{input("destination", "string"), input("payload", "string"), optional("encoding", "string", "text"), optional("timeout_ms", "number", float64(2000))},
			[]Port{output("ok", "boolean"), output("error", "string"), output("bytes", "number"), output("duration_ms", "number")}, []string{"next"}},
		{"start_timer", "Start timer", "Timing", "Create a timer for this run (up to 128). Connect its timer output to Elapsed time. Uses a monotonic local clock; it does not synchronize executors.", false,
			[]Port{}, []Port{output("timer", "string")}, []string{"next"}},
		{"elapsed", "Elapsed time", "Timing", "Measure milliseconds since a Start timer action in this run. Reading a timer does not reset it.", false,
			[]Port{input("timer", "string")}, []Port{output("duration_ms", "number")}, []string{"next"}},
		{"create_collection", "Create sample collection", "Data", "Create an empty run-local sample collection (up to 32). Place before Repeat; connect collection to Collect sample and Read samples.", false,
			[]Port{}, []Port{output("collection", "string")}, []string{"next"}},
		{"collect", "Collect sample", "Data", "Append a snapshot to a collection. Survives Repeat iterations. Bounded to 1024 samples and 48 KiB per collection, with 256 KiB across the run.", false,
			[]Port{input("collection", "string"), input("value", "any")}, []Port{output("count", "number")}, []string{"next"}},
		{"read_collection", "Read samples", "Data", "Read an independent list of collected samples, for statistics or result output.", false,
			[]Port{input("collection", "string")}, []Port{output("values", "any"), output("count", "number")}, []string{"next"}},
		{"reset_collection", "Clear samples", "Data", "Empty a collection and release its sample storage. The collection handle remains usable.", false,
			[]Port{input("collection", "string")}, []Port{output("count", "number")}, []string{"next"}},
		{"phase_barrier", "Wait for phase", "Experiment", "Wait until all experiment participants reach this named phase and repetition. Every participant must call it in the same order. A timeout reports missing peers; release does not synchronize clocks or guarantee simultaneous execution.", false,
			[]Port{input("phase", "string"), optional("timeout_ms", "number", float64(5000))},
			[]Port{output("ok", "boolean"), output("error", "string"), output("phase", "string"), output("generation", "number"), output("missing", "strings"), output("duration_ms", "number")}, []string{"next"}},
	}
}

func exchangeOutputs() []Port {
	return []Port{output("ok", "boolean"), output("error", "string"), output("response", "string"), output("response_base64", "string"), output("received_bytes", "number"), output("sent_bytes", "number"), output("duration_ms", "number"), output("complete", "boolean"), output("truncated", "boolean")}
}
