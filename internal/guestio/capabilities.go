// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guestio

// Optional host functions added after the original recoverable socket API.
const (
	TLSInspect                   = "tls_inspect"
	HopProbe                     = "hop_probe"
	ReceiveUDP                   = "receive_udp"
	ReplyUDP                     = "reply_udp"
	SCIONPaths                   = "scion_paths"
	SCIONSelectPath              = "scion_select_path"
	SCIONExchangeFunction        = "scion_exchange"
	SCIONListenerAddressFunction = "scion_listener_address"
	SCIONReceive                 = "scion_receive"
	SCIONReply                   = "scion_reply"
	SCIONQUICEchoStart           = "scion_quic_echo_start"
	SCIONQUICEchoStop            = "scion_quic_echo_stop"
	SCIONQUICExchangeFunction    = "scion_quic_exchange"
	MeshStartFunction            = "mesh_start"
	MeshSnapshotFunction         = "mesh_snapshot"
	MeshStopFunction             = "mesh_stop"
	MeshTransferFunction         = "mesh_transfer"
)

// SupportedHostFunctions returns the optional exports provided by this build.
// Protocol permissions, raw socket availability and listener admission remain
// separate requirements; an export alone does not grant access to a target.
func SupportedHostFunctions() []string {
	return []string{
		Module + "." + HopProbe,
		Module + "." + MeshSnapshotFunction,
		Module + "." + MeshStartFunction,
		Module + "." + MeshStopFunction,
		Module + "." + MeshTransferFunction,
		Module + "." + ReceiveUDP,
		Module + "." + ReplyUDP,
		Module + "." + SCIONExchangeFunction,
		Module + "." + SCIONListenerAddressFunction,
		Module + "." + SCIONPaths,
		Module + "." + SCIONQUICEchoStart,
		Module + "." + SCIONQUICEchoStop,
		Module + "." + SCIONQUICExchangeFunction,
		Module + "." + SCIONReceive,
		Module + "." + SCIONReply,
		Module + "." + SCIONSelectPath,
		Module + "." + TLSInspect,
	}
}
