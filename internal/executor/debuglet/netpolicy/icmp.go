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
	"fmt"
	"net"
	"sync"
)

// ICMPPermitted reports whether this process may open the raw ICMPv4 sockets
// the connect_icmp4 import needs. It is a real attempt to open one, not a
// property of the packet counter or of any configuration key: a host that
// cannot open the socket must not advertise the capability, and a job that
// asks for it must be refused before it dials.
//
// The answer is determined once. Process privileges do not change while the
// executor runs, and repeating the probe on every connect would open a raw
// socket for every guest call.
var ICMPPermitted = sync.OnceValue(probeICMP)

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
