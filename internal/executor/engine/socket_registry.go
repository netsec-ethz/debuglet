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
	"fmt"
	"net/netip"
	"sync"
	"syscall"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"

	"debuglet/pkg/tagger"
)

// SocketRegistry manages the lifecycle of all open sockets within a single
// WASM execution. Handles are stable int32 indices into the registry.
type SocketRegistry struct {
	mu      sync.Mutex
	sockets []Socket
}

// Add registers a new socket and returns its handle.
func (r *SocketRegistry) Add(s Socket) int32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sockets = append(r.sockets, s)
	return int32(len(r.sockets) - 1)
}

// Get retrieves the socket for the given handle.
func (r *SocketRegistry) Get(handle int32) (Socket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if handle < 0 || int(handle) >= len(r.sockets) {
		return nil, fmt.Errorf("invalid socket handle %d", handle)
	}
	if r.sockets[handle] == nil {
		return nil, fmt.Errorf("socket handle %d has been closed", handle)
	}
	return r.sockets[handle], nil
}

// Close closes the socket for the given handle and marks the slot as nil.
func (r *SocketRegistry) Close(handle int32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if handle < 0 || int(handle) >= len(r.sockets) {
		return fmt.Errorf("invalid socket handle %d", handle)
	}
	s := r.sockets[handle]
	if s == nil {
		return nil // already closed
	}
	r.sockets[handle] = nil
	return s.Close()
}

// CloseAll closes all open sockets.
func (r *SocketRegistry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, s := range r.sockets {
		if s != nil {
			_ = s.Close()
			r.sockets[i] = nil
		}
	}
}

// SCIONConn wraps a SCION/UDP connection and its associated PathSelector.
// It replaces the former ScionDialWrapper.
type SCIONConn struct {
	conn     *pan.Conn
	selector *PathSelector
}

// SCIONConnRegistry manages lazily-dialled SCION connections keyed by
// address index. The capacity is fixed at construction time to match the
// number of addresses provided to the WASM module.
type SCIONConnRegistry struct {
	mu    sync.Mutex
	conns []*SCIONConn
}

// NewSCIONConnRegistry creates a registry pre-sized for the given number of addresses.
func NewSCIONConnRegistry(capacity int) *SCIONConnRegistry {
	return &SCIONConnRegistry{conns: make([]*SCIONConn, capacity)}
}

// GetOrDial returns the existing SCIONConn for the given address index, or
// dials a new one if none exists yet.
func (r *SCIONConnRegistry) GetOrDial(
	ctx context.Context,
	addresses []string,
	addrIdx int32,
	sugar *zap.SugaredLogger,
	pktTagger tagger.TaggerInterface,
) (*SCIONConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if addrIdx < 0 || int(addrIdx) >= len(r.conns) {
		return nil, fmt.Errorf("invalid address index %d (have %d addresses)", addrIdx, len(r.conns))
	}

	if r.conns[addrIdx] != nil {
		return r.conns[addrIdx], nil
	}

	udpAddr, err := pan.ResolveUDPAddr(ctx, addresses[addrIdx])
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SCION address %q: %w", addresses[addrIdx], err)
	}

	sugar.Debugw("SCIONConnRegistry dialling", "udpAddr", udpAddr)

	selector := NewPathSelector()
	conn, err := pan.DialUDP(ctx, netip.AddrPort{}, udpAddr, nil, selector)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SCION address %q: %w", addresses[addrIdx], err)
	}

	if pktTagger != nil {
		if sc, ok := conn.(interface{ SyscallConn() (syscall.RawConn, error) }); ok {
			rawConn, err := sc.SyscallConn()
			if err == nil {
				rawConn.Control(func(fd uintptr) {
					pktTagger.SetSocketMark(int(fd))
				})
			}
		}
	}

	sc := &SCIONConn{conn: &conn, selector: selector}
	r.conns[addrIdx] = sc
	return sc, nil
}

// CloseAll closes all open SCION connections.
func (r *SCIONConnRegistry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, sc := range r.conns {
		if sc != nil && sc.conn != nil {
			_ = (*sc.conn).Close()
			r.conns[i] = nil
		}
	}
}
