// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tagger

// Tagging modes of one address family or transport.
const (
	// ModeEBPF is the kernel tagger on TC egress: every IPv4 packet of a
	// marked socket, TCP, TLS, UDP and ICMP alike, carries the run's tag.
	ModeEBPF = "ebpf"
	// ModeUserspace is the pure-Go tagger: UDP and ICMP datagrams to IPv4
	// destinations are sent through a raw socket and tagged; TCP and TLS
	// segments are written by the kernel and stay untagged.
	ModeUserspace = "userspace"
	// ModeNone is untagged traffic.
	ModeNone = "none"
)

// Mode is how a run's packets are tagged, per address family and for SCION.
// Neither tagger tags IPv6 yet, and SCION sockets cannot be marked, so IPv6
// and SCION are always ModeNone in this build.
type Mode struct {
	IPv4  string
	IPv6  string
	SCION string
}

// Untagged is the mode of a run without a tagger.
var Untagged = Mode{IPv4: ModeNone, IPv6: ModeNone, SCION: ModeNone}

// RefusesIPv6 reports whether a run in this mode refuses IPv6 traffic rather
// than send it untagged: a run whose IPv4 packets are all tagged in the kernel
// expects attribution, and an IPv6 packet it sent would silently lack it.
func (m Mode) RefusesIPv6() bool { return m.IPv4 == ModeEBPF && m.IPv6 == ModeNone }
