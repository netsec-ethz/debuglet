// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netpolicy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
)

// ICMP probe reasons, reported with an unavailable ICMP capability.
const (
	// ICMPDisabled: the operator's network policy switches ICMP off.
	ICMPDisabled = "disabled"
	// ICMPNotPermitted: the process may not open raw sockets (CAP_NET_RAW).
	ICMPNotPermitted = "not_permitted"
	// ICMPPingSocketOnly: raw sockets are refused, but an unprivileged ping
	// socket opens. Guests need raw sockets, so ICMP remains unavailable.
	ICMPPingSocketOnly = "ping_socket_only"
	// ICMPUnsupported: the raw socket failed for another reason.
	ICMPUnsupported = "unsupported"
)

// ICMPPermitted reports whether this process may open the raw ICMPv4 sockets
// the connect_icmp4 import needs. It is a real attempt to open one, not a
// property of the packet counter or of any configuration key: a host that
// cannot open the socket must not advertise the capability, and a job that
// asks for it must be refused before it dials.
//
// The first call probes; later calls return the latest answer. Repeating the
// probe on every connect would open a raw socket for every guest call, so the
// executor refreshes it on the capability cadence with RefreshICMP instead.
func ICMPPermitted() error {
	icmpState.mu.Lock()
	defer icmpState.mu.Unlock()
	if !icmpState.probed {
		icmpState.err, icmpState.probed = probeICMP(), true
	}
	return icmpState.err
}

// RefreshICMP probes again and records the answer for ICMPPermitted. A refusal
// comes with its reason: ICMPNotPermitted, ICMPPingSocketOnly or
// ICMPUnsupported. Both are empty when raw sockets are permitted.
func RefreshICMP() (reason string, err error) {
	err = probeICMP()
	icmpState.mu.Lock()
	icmpState.err, icmpState.probed = err, true
	icmpState.mu.Unlock()
	return icmpReason(err, probePingSocket), err
}

var icmpState struct {
	mu     sync.Mutex
	probed bool
	err    error
}

// icmpReason classifies a raw-socket failure. Only a permission refusal tries
// the unprivileged ping socket, which then only refines the reason.
func icmpReason(err error, pingSocket func() error) string {
	switch {
	case err == nil:
		return ""
	case !errors.Is(err, os.ErrPermission):
		return ICMPUnsupported
	case pingSocket() == nil:
		return ICMPPingSocketOnly
	default:
		return ICMPNotPermitted
	}
}

// probeICMP opens and immediately closes one raw ICMPv4 socket. It binds the
// unspecified address, so it sends nothing and reaches no destination.
func probeICMP() error {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("raw ICMPv4 sockets are not permitted: %w", err)
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("failed to release the ICMPv4 probe socket: %w", err)
	}
	return nil
}
