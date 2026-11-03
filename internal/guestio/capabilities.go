// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guestio

// Optional host functions added after the original recoverable socket API.
const (
	TLSInspect   = "tls_inspect"
	HopProbe     = "hop_probe"
	ReceiveUDP   = "receive_udp"
	ReplyUDP     = "reply_udp"
	MeshStart    = "mesh_start"
	MeshSnapshot = "mesh_snapshot"
	MeshStop     = "mesh_stop"
	MeshTransfer = "mesh_transfer"
)

// SupportedHostFunctions returns the optional exports provided by this build.
// Protocol permissions, raw socket availability and listener admission remain
// separate requirements; an export alone does not grant access to a target.
func SupportedHostFunctions() []string {
	return []string{
		Module + "." + HopProbe,
		Module + "." + MeshSnapshot,
		Module + "." + MeshStart,
		Module + "." + MeshStop,
		Module + "." + MeshTransfer,
		Module + "." + ReceiveUDP,
		Module + "." + ReplyUDP,
		Module + "." + TLSInspect,
	}
}
