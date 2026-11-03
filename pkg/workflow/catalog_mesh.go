// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func experimentBlock(id string) bool {
	switch id {
	case "send_message", "await_message", "phase_barrier", "for_each_peer", "experiment_peers", "udp_probe_start", "udp_probe_snapshot", "udp_probe_stop", "tcp_responder_start", "tcp_transfer", "tcp_responder_stop":
		return true
	}
	return false
}

func loopBlock(id string) bool {
	return id == "repeat" || id == "for_each" || id == "every" || id == "for_each_peer"
}

func meshCatalog() []Block {
	service := []Port{input("service", "string")}
	ok := []Port{output("ok", "boolean")}
	return []Block{
		{"every", "Every", "Control", "Run body on a fixed cadence for at most 24 hours. Missed ticks are skipped, not replayed. Each iteration has its own 1000-action budget; results remain bounded. In an experiment, ticks use its common start (not synchronized clocks).", false, []Port{input("interval_ms", "number"), input("duration_ms", "number"), optional("immediate", "boolean", true), optional("start_delay_ms", "number", float64(5000))}, []Port{output("iteration", "number"), output("elapsed_ms", "number"), output("missed_intervals", "number")}, []string{"body", "done"}},
		{"for_each_peer", "Take turns with peers", "Experiment", "Visit every directed participant pair in deterministic, non-overlapping time slots. Only the sender executes body; receivers run in the background. A late sender uses only the remaining slot. Requires an experiment; host clock error still affects timing.", false, []Port{optional("slot_ms", "number", float64(30000))}, []Port{output("peer", "string"), output("turn", "number")}, []string{"body", "done"}},
		{"experiment_peers", "Experiment peers", "Experiment", "Read the admitted participant roster and their listener addresses.", false, []Port{}, []Port{output("self", "string"), output("peers", "any"), output("participants", "strings"), output("index", "number")}, []string{"next"}},
		{"udp_probe_start", "Start UDP probes", "Network", "Start bounded background probes to admitted peers, measuring round-trip timing and receiver-confirmed directional loss. Read completed windows with UDP probe snapshot.", false, []Port{optional("interval_ms", "number", float64(1000)), optional("window_ms", "number", float64(300000)), optional("duration_ms", "number", float64(86400000))}, []Port{output("service", "string")}, []string{"next"}},
		{"udp_probe_snapshot", "UDP probe snapshot", "Network", "Read completed probe windows without stopping the receiver. Missing windows and failures stay explicit.", false, service, []Port{output("ok", "boolean"), output("error", "string"), output("rows", "any"), output("window_start_ms", "number"), output("window_end_ms", "number"), output("skipped_windows", "number")}, []string{"next"}},
		{"udp_probe_stop", "Stop UDP probes", "Network", "Stop this run's background UDP measurement service.", false, service, ok, []string{"next"}},
		{"tcp_responder_start", "Start TCP receiver", "Network", "Serve bounded TCP transfers from admitted peers in the background. Owns the run's TCP listener until stopped; cannot share it with message channels.", false, []Port{optional("duration_ms", "number", float64(86400000)), optional("max_bytes", "number", float64(33554432)), optional("max_transfer_ms", "number", float64(10000))}, []Port{output("service", "string")}, []string{"next"}},
		{"tcp_transfer", "TCP transfer", "Network", "Send a bounded payload to an admitted peer and report receiver-confirmed goodput. Use Take turns with peers to avoid simultaneous transfers; its slot deadline bounds this operation.", false, []Port{input("peer", "string"), optional("bytes", "number", float64(33554432)), optional("timeout_ms", "number", float64(10000))}, []Port{output("ok", "boolean"), output("error", "string"), output("sent_bytes", "number"), output("received_bytes", "number"), output("duration_ms", "number"), output("goodput_mbps", "number"), output("peer", "string")}, []string{"next"}},
		{"tcp_responder_stop", "Stop TCP receiver", "Network", "Stop this run's background TCP responder and release its listener.", false, service, ok, []string{"next"}},
	}
}
