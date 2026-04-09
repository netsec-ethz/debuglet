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

package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
)

// Wrapper for TCP/TLS connection objects
type ConnWrapper struct {
	conn *interface{}

	tcpConn *net.TCPConn
	tlsConn *tls.Conn
	tls     bool
}

// Wrapper for SCION connection objects
type ScionDialWrapper struct {
	conn     *pan.Conn
	selector *DebugletSelector
	failed   bool
}

func (c ConnWrapper) Read(data []byte) (int, error) {
	if c.tls {
		return c.tlsConn.Read(data)
	}
	return c.tcpConn.Read(data)
}

func (c ConnWrapper) Write(data []byte) (int, error) {
	if c.tls {
		return c.tlsConn.Write(data)
	}
	return c.tcpConn.Write(data)
}

func (c ConnWrapper) Close() error {
	if c.tls {
		return c.tlsConn.Close()
	}
	return c.tcpConn.Close()
}

// Returned a dialled SCION connection to the given address (given as an index).
// If the address is already dialed (i.e. present in dialedScionConnections), the corresponding connection is returned.
// Otherwise a new connection is dialled.
func dialScion(
	dialedScionConnections *[]*ScionDialWrapper,
	addresses []string,
	address int32,
	ctx context.Context,
	sugar *zap.SugaredLogger,
) (*ScionDialWrapper, error) {
	if (*dialedScionConnections)[address] != nil {
		return (*dialedScionConnections)[address], nil
	}

	udpAddr, err := pan.ResolveUDPAddr(ctx, addresses[address])
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SCION address: %w", err)
	}

	sugar.Debugw("dialScion dialling", "udpAddr", udpAddr)

	selector := NewDebugletSelector()

	conn, err := pan.DialUDP(ctx, netip.AddrPort{}, udpAddr, nil, selector)
	if err != nil {
		return nil, fmt.Errorf("failed to dial the given address: %w", err)
	}

	(*dialedScionConnections)[address] = &ScionDialWrapper{
		conn:     &conn,
		selector: selector,
	}
	return (*dialedScionConnections)[address], nil
}
