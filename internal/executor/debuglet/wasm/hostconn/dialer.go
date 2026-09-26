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
	"fmt"
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
	marker Marker
}

// Marker puts a socket under a run's packet attribution.
type Marker interface {
	SetSocketMark(fd int) error
}

// NewDialer returns a dialer that consults guard for every socket it opens and
// marks every admitted socket with marker before it is connected. A nil marker,
// including a nil tagger converted to a Marker, means no marking.
func NewDialer(guard Guard, marker Marker) (*HostDialer, error) {
	if guard == nil {
		return nil, errors.New("received <nil> policy guard")
	}
	hd := &HostDialer{guard: guard, marker: marker}
	hd.dialer = &net.Dialer{Control: hd.Control}
	return hd, nil
}

// Control is the net.Dialer control hook. The operating system calls it with
// the resolved address after the socket exists and before it is connected, so
// a refusal here is a destination that was never contacted, and a mark set
// here covers the socket's first packet. A socket that cannot be marked is not
// connected.
func (hd *HostDialer) Control(network, address string, raw syscall.RawConn) error {
	if err := hd.guard.CheckSocket(network, address); err != nil {
		return err
	}
	if hd.marker == nil {
		return nil
	}
	return MarkSocket(raw, hd.marker)
}

// MarkSocket applies marker to the socket behind raw.
func MarkSocket(raw syscall.RawConn, marker Marker) error {
	var markErr error
	if err := raw.Control(func(fd uintptr) { markErr = marker.SetSocketMark(int(fd)) }); err != nil {
		return fmt.Errorf("mark socket: %w", err)
	}
	if markErr != nil {
		return fmt.Errorf("mark socket: %w", markErr)
	}
	return nil
}

func (hd *HostDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return hd.dialer.DialContext(ctx, network, address)
}
