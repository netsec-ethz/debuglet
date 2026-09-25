// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
)

type ISocketRegistry interface {
	Add(s Socket) (int32, error)
	Close(handle int32) error
	CloseAll() error
	Get(handle int32) (Socket, error)
}

// SocketRegistry manages the lifecycle of all open sockets within a single
// WASM execution. Handles are stable int32 indices into the registry.
type SocketRegistry struct {
	mu           sync.Mutex
	sockets      []*socketEntry
	closed       bool
	closeOnce    sync.Once
	closeErr     error
	lateCloseErr error
}

// Each entry retains its immutable connection and its one close completion.
// Detached handles cannot be retrieved, but another closer can still join them.
type socketEntry struct {
	socket   Socket
	detached bool // protected by the registry mutex
	once     sync.Once
	err      error
}

func (e *socketEntry) close() error {
	e.once.Do(func() { e.err = e.socket.Close() })
	return e.err
}

// Add consumes s, including when terminal admission rejects it.
func (r *SocketRegistry) Add(s Socket) (int32, error) {
	if s == nil {
		return -1, errors.New("nil socket")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		err := s.Close()
		r.mu.Lock()
		r.lateCloseErr = errors.Join(r.lateCloseErr, err)
		r.mu.Unlock()
		return -1, errors.Join(net.ErrClosed, err)
	}
	r.sockets = append(r.sockets, &socketEntry{socket: s})
	handle := int32(len(r.sockets) - 1)
	r.mu.Unlock()
	return handle, nil
}

func (r *SocketRegistry) Get(handle int32) (Socket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if handle < 0 || int(handle) >= len(r.sockets) {
		return nil, fmt.Errorf("invalid socket handle %d", handle)
	}
	entry := r.sockets[handle]
	if entry.detached {
		return nil, fmt.Errorf("socket handle %d has been closed: %w", handle, net.ErrClosed)
	}
	return entry.socket, nil
}

func (r *SocketRegistry) Close(handle int32) error {
	r.mu.Lock()
	if handle < 0 || int(handle) >= len(r.sockets) {
		r.mu.Unlock()
		return fmt.Errorf("invalid socket handle %d", handle)
	}
	entry := r.sockets[handle]
	entry.detached = true
	r.mu.Unlock()
	return entry.close()
}

// CloseAll permanently stops admission before invoking any external Close.
// sync.Once also joins concurrent callers, including a held underlying Close.
func (r *SocketRegistry) CloseAll() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		entries := append([]*socketEntry(nil), r.sockets...)
		for _, entry := range entries {
			entry.detached = true
		}
		r.mu.Unlock()
		for _, entry := range entries {
			r.closeErr = errors.Join(r.closeErr, entry.close())
		}
	})
	r.mu.Lock()
	lateErr := r.lateCloseErr
	r.mu.Unlock()
	return errors.Join(r.closeErr, lateErr)
}

func (r *SocketRegistry) All() []Socket {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Socket, len(r.sockets))
	for i, entry := range r.sockets {
		if !entry.detached {
			result[i] = entry.socket
		}
	}
	return result
}

// SCIONConn wraps a SCION/UDP connection and its associated PathSelector.
// It replaces the former ScionDialWrapper.
type SCIONConn struct {
	Conn     *pan.Conn
	Selector *PathSelector
}

// SCIONConnRegistry manages lazily-dialled SCION connections keyed by
// address index. The capacity is fixed at construction time to match the
// number of addresses provided to the WASM module.
type SCIONConnRegistry struct {
	mu           sync.Mutex
	conns        map[string]*scionEntry
	closed       bool
	closeOnce    sync.Once
	closeErr     error
	lateCloseErr error
	// Per-instance dial seam keeps local ownership tests off SCION networks.
	dial func(context.Context, string, *zap.SugaredLogger, tagger.TaggerInterface) (*SCIONConn, error)
}

type scionEntry struct {
	done     chan struct{}
	cancel   context.CancelFunc
	conn     *SCIONConn
	err      error
	once     sync.Once
	closeErr error
}

func (e *scionEntry) close() error {
	<-e.done
	e.once.Do(func() {
		if e.conn != nil && e.conn.Conn != nil {
			e.closeErr = (*e.conn.Conn).Close()
		}
	})
	return e.closeErr
}

func NewSCIONConnRegistry(capacity int) *SCIONConnRegistry {
	return &SCIONConnRegistry{conns: make(map[string]*scionEntry, capacity)}
}

func (r *SCIONConnRegistry) GetOrDial(ctx context.Context, addr string, sugar *zap.SugaredLogger, pktTagger tagger.TaggerInterface) (*SCIONConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	if entry, ok := r.conns[addr]; ok {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-entry.done:
			r.mu.Lock()
			closed := r.closed
			r.mu.Unlock()
			if closed {
				return nil, net.ErrClosed
			}
			return entry.conn, entry.err
		}
	}
	dialCtx, cancel := context.WithCancel(ctx)
	entry := &scionEntry{done: make(chan struct{}), cancel: cancel}
	if r.conns == nil {
		r.conns = make(map[string]*scionEntry)
	}
	r.conns[addr] = entry
	dial := r.dial
	if dial == nil {
		dial = dialSCION
	}
	r.mu.Unlock()
	conn, err := dial(dialCtx, addr, sugar, pktTagger)
	cancel()
	r.mu.Lock()
	closed := r.closed
	entry.conn, entry.err = conn, err
	// Failed dials can be retried while admission remains open.
	if err != nil && !closed {
		delete(r.conns, addr)
	}
	close(entry.done)
	r.mu.Unlock()
	if closed {
		return nil, errors.Join(net.ErrClosed, entry.close())
	}
	if err != nil && conn != nil {
		closeErr := entry.close()
		r.mu.Lock()
		r.lateCloseErr = errors.Join(r.lateCloseErr, closeErr)
		r.mu.Unlock()
		return nil, errors.Join(err, closeErr)
	}
	return conn, err
}

func dialSCION(ctx context.Context, addr string, sugar *zap.SugaredLogger, pktTagger tagger.TaggerInterface) (*SCIONConn, error) {
	udpAddr, err := pan.ResolveUDPAddr(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SCION address %q: %w", addr, err)
	}
	sugar.Debugw("SCIONConnRegistry dialling", "udpAddr", udpAddr)
	selector := NewPathSelector()
	conn, err := pan.DialUDP(ctx, netip.AddrPort{}, udpAddr, nil, selector)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SCION address %q: %w", addr, err)
	}
	if pktTagger != nil {
		if sc, ok := conn.(interface {
			SyscallConn() (syscall.RawConn, error)
		}); ok {
			if raw, err := sc.SyscallConn(); err == nil {
				_ = raw.Control(func(fd uintptr) { pktTagger.SetSocketMark(int(fd)) })
			}
		}
	}
	return &SCIONConn{Conn: &conn, Selector: selector}, nil
}

func (r *SCIONConnRegistry) CloseAll() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		entries := make([]*scionEntry, 0, len(r.conns))
		for _, entry := range r.conns {
			entries = append(entries, entry)
		}
		r.mu.Unlock()
		for _, entry := range entries {
			entry.cancel()
		}
		for _, entry := range entries {
			r.closeErr = errors.Join(r.closeErr, entry.close())
		}
	})
	r.mu.Lock()
	lateErr := r.lateCloseErr
	r.mu.Unlock()
	return errors.Join(r.closeErr, lateErr)
}
