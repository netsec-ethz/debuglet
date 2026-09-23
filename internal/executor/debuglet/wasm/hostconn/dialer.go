// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

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

package hostconn

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// Guard is the network policy decision a dialer applies to the address the
// operating system is about to connect to. It is the last gate in front of
// connect: returning an error from it means no packet is sent.
type Guard interface {
	CheckSocket(network, address string) error
}

// HostDialer dials a guest's connection under a Guard. It holds no policy of
// its own: everything it refuses, it refuses because the guard did.
type HostDialer struct {
	dialer *net.Dialer
	guard  Guard
}

// NewDialer returns a dialer that consults guard for every socket it opens.
func NewDialer(guard Guard) (*HostDialer, error) {
	if guard == nil {
		return nil, errors.New("received <nil> policy guard")
	}
	hd := &HostDialer{guard: guard}
	hd.dialer = &net.Dialer{Control: hd.Control}
	return hd, nil
}

// Control is the net.Dialer control hook. The operating system calls it with
// the resolved address after the socket exists and before it is connected, so
// a refusal here is a destination that was never contacted.
func (hd *HostDialer) Control(network, address string, _ syscall.RawConn) error {
	return hd.guard.CheckSocket(network, address)
}

func (hd *HostDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return hd.dialer.DialContext(ctx, network, address)
}
