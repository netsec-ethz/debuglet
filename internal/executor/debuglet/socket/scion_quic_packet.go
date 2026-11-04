// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

type scionQUICRoute struct {
	path    *pan.Path
	expires time.Time
}

type scionQUICPacketConn struct {
	pan.ListenConn
	ctx      context.Context
	cancel   context.CancelFunc
	hooks    SCIONQUICHooks
	target   *pan.UDPAddr
	path     *pan.Path
	readMu   sync.Mutex
	buffer   [65535]byte
	mu       sync.Mutex
	routes   map[pan.UDPAddr]scionQUICRoute
	once     sync.Once
	closeErr error
	sent     atomic.Bool
}

func newSCIONQUICPacketConn(ctx context.Context, conn pan.ListenConn, hooks SCIONQUICHooks) *scionQUICPacketConn {
	owned, cancel := context.WithCancel(ctx)
	return &scionQUICPacketConn{ListenConn: conn, ctx: owned, cancel: cancel, hooks: hooks, routes: make(map[pan.UDPAddr]scionQUICRoute)}
}

func (c *scionQUICPacketConn) Close() error {
	c.once.Do(func() { c.cancel(); c.closeErr = c.ListenConn.Close() })
	return c.closeErr
}

func (c *scionQUICPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if err := c.ctx.Err(); err != nil {
			return 0, nil, context.Cause(c.ctx)
		}
		n, peer, path, err := c.ListenConn.ReadFromVia(c.buffer[:])
		if err != nil {
			return 0, nil, err
		}
		if n < 0 || n > len(c.buffer) {
			return 0, nil, errors.New("invalid SCION QUIC datagram length")
		}
		if c.target != nil && peer != *c.target {
			continue
		}
		if err := c.hooks.Admit(c.ctx, peer); err != nil {
			continue
		}
		if err := c.hooks.Account(c.ctx, peer, false, n); err != nil {
			return 0, nil, err
		}
		if n > len(buffer) {
			continue
		}
		if c.target == nil {
			c.mu.Lock()
			c.prune()
			_, known := c.routes[peer]
			if !known && len(c.routes) >= 8 {
				c.mu.Unlock()
				continue
			}
			c.routes[peer] = scionQUICRoute{path: path, expires: time.Now().Add(10 * time.Second)}
			c.mu.Unlock()
		}
		copy(buffer, c.buffer[:n])
		return n, peer, nil
	}
}

func (c *scionQUICPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	peer, ok := address.(pan.UDPAddr)
	if !ok {
		return 0, errors.New("invalid SCION QUIC peer")
	}
	if err := c.ctx.Err(); err != nil {
		return 0, context.Cause(c.ctx)
	}
	if c.target != nil && peer != *c.target {
		return 0, errors.New("SCION QUIC peer changed")
	}
	if err := c.hooks.Admit(c.ctx, peer); err != nil {
		return 0, err
	}
	path := c.path
	if c.target == nil {
		c.mu.Lock()
		c.prune()
		route, exists := c.routes[peer]
		c.mu.Unlock()
		if !exists {
			return 0, ErrSCIONPathUnavailable
		}
		path = route.path
	}
	local, ok := c.LocalAddr().(pan.UDPAddr)
	if !ok {
		return 0, errors.New("invalid SCION QUIC local address")
	}
	if local.IA != peer.IA {
		if path == nil || path.Source != local.IA || path.Destination != peer.IA || !path.Expiry.After(time.Now()) {
			return 0, ErrSCIONPathUnavailable
		}
	} else {
		path = nil
	}
	if err := c.hooks.Account(c.ctx, peer, true, len(payload)); err != nil {
		return 0, err
	}
	// Accounting may wait for a budget; do not transmit an expired path or
	// cancelled operation after that wait.
	if err := c.ctx.Err(); err != nil {
		return 0, context.Cause(c.ctx)
	}
	if path != nil && !path.Expiry.After(time.Now()) {
		return 0, ErrSCIONPathUnavailable
	}
	n, err := c.ListenConn.WriteToVia(payload, peer, path)
	if n > 0 {
		c.sent.Store(true)
	}
	return n, err
}

func (c *scionQUICPacketConn) prune() {
	now := time.Now()
	for peer, route := range c.routes {
		if !route.expires.After(now) {
			delete(c.routes, peer)
		}
	}
}
func (c *scionQUICPacketConn) forget(address net.Addr) {
	if peer, ok := address.(pan.UDPAddr); ok {
		c.mu.Lock()
		delete(c.routes, peer)
		c.mu.Unlock()
	}
}

type scionQUICNoopReplySelector struct{}

func (*scionQUICNoopReplySelector) Initialize(pan.UDPAddr)                          {}
func (*scionQUICNoopReplySelector) Record(pan.UDPAddr, *pan.Path)                   {}
func (*scionQUICNoopReplySelector) Path(pan.UDPAddr) *pan.Path                      { return nil }
func (*scionQUICNoopReplySelector) PathDown(pan.PathFingerprint, pan.PathInterface) {}
func (*scionQUICNoopReplySelector) Close() error                                    { return nil }

// NewBoundedSCIONReplySelector bounds the pre-admission peer cache maintained
// by PAN. Raw SCION replies retain their behavior without an unbounded peer map.
func NewBoundedSCIONReplySelector() pan.ReplySelector {
	return &boundedSCIONReplySelector{paths: make(map[pan.UDPAddr]scionQUICRoute)}
}

type boundedSCIONReplySelector struct {
	mu    sync.Mutex
	paths map[pan.UDPAddr]scionQUICRoute
}

func (*boundedSCIONReplySelector) Initialize(pan.UDPAddr) {}
func (s *boundedSCIONReplySelector) Record(peer pan.UDPAddr, path *pan.Path) {
	if path == nil || !path.Expiry.After(time.Now()) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for addr, route := range s.paths {
		if !route.expires.After(now) || !route.path.Expiry.After(now) {
			delete(s.paths, addr)
		}
	}
	if _, exists := s.paths[peer]; !exists && len(s.paths) >= 32 {
		return
	}
	s.paths[peer] = scionQUICRoute{path: path, expires: now.Add(time.Minute)}
}
func (s *boundedSCIONReplySelector) Path(peer pan.UDPAddr) *pan.Path {
	s.mu.Lock()
	defer s.mu.Unlock()
	route, exists := s.paths[peer]
	if !exists || !route.expires.After(time.Now()) || !route.path.Expiry.After(time.Now()) {
		delete(s.paths, peer)
		return nil
	}
	return route.path
}
func (s *boundedSCIONReplySelector) PathDown(fp pan.PathFingerprint, iface pan.PathInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for peer, route := range s.paths {
		if route.path.Fingerprint == fp || isInterfaceOnPath(route.path, iface) {
			delete(s.paths, peer)
		}
	}
}
func (s *boundedSCIONReplySelector) Close() error {
	s.mu.Lock()
	clear(s.paths)
	s.mu.Unlock()
	return nil
}
