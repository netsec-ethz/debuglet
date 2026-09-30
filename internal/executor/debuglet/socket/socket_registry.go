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
	budget       *Budget
	closed       bool
	closeOnce    sync.Once
	closeErr     error
	lateCloseErr error
}

// Each entry retains its immutable connection and its one close completion.
// Detached handles cannot be retrieved, but another closer can still join them.
type socketEntry struct {
	socket      Socket
	detached    bool // protected by the registry mutex
	once        sync.Once
	err         error
	reservation *Reservation
}

func (e *socketEntry) close() error {
	e.once.Do(func() {
		e.err = e.socket.Close()
		e.reservation.Release()
	})
	return e.err
}

// NewSocketRegistry gives every handle the same run budget as its listeners.
func NewSocketRegistry(budget *Budget) *SocketRegistry {
	return &SocketRegistry{budget: budget}
}

// SocketReservation also binds an attempt to its registry. A reservation can
// publish one socket, and admission after terminal closure still consumes it.
type SocketReservation struct {
	registry    *SocketRegistry
	reservation *Reservation
	claimed     bool // protected by registry.mu
}

func (r *SocketRegistry) Reserve(descriptors int) (*SocketReservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if r.budget == nil {
		// A standalone zero-value registry has the same finite run bounds.
		r.budget = NewBudget(DefaultLimits(), NewDescriptorBudget(DefaultNodeDescriptors))
	}
	reservation, err := r.budget.ReserveSocket(descriptors)
	if err != nil {
		return nil, err
	}
	return &SocketReservation{registry: r, reservation: reservation}, nil
}

// Release abandons an attempt that did not publish a socket.
func (s *SocketReservation) Release() {
	if s == nil {
		return
	}
	s.registry.mu.Lock()
	if !s.claimed {
		s.claimed = true
		s.reservation.Release()
	}
	s.registry.mu.Unlock()
}

// Add consumes s, including when quota or terminal admission rejects it.
// Host operations reserve before creating a socket and use AddReserved.
func (r *SocketRegistry) Add(s Socket) (int32, error) {
	if s == nil {
		return -1, errors.New("nil socket")
	}
	reservation, err := r.Reserve(1)
	if err != nil {
		return -1, errors.Join(err, r.closeRejected(s))
	}
	return r.AddReserved(s, reservation)
}

func (r *SocketRegistry) closeRejected(s Socket) error {
	err := s.Close()
	r.mu.Lock()
	r.lateCloseErr = errors.Join(r.lateCloseErr, err)
	r.mu.Unlock()
	return err
}

// AddReserved consumes the socket and its reservation on every path.
func (r *SocketRegistry) AddReserved(s Socket, reservation *SocketReservation) (int32, error) {
	if s == nil {
		reservation.Release()
		return -1, errors.New("nil socket")
	}
	r.mu.Lock()
	if reservation == nil || reservation.registry != r || reservation.claimed {
		r.mu.Unlock()
		reservation.Release()
		return -1, errors.Join(errors.New("invalid socket reservation"), r.closeRejected(s))
	}
	reservation.claimed = true
	if r.closed {
		r.mu.Unlock()
		err := r.closeRejected(s)
		reservation.reservation.Release()
		return -1, errors.Join(net.ErrClosed, err)
	}
	r.sockets = append(r.sockets, &socketEntry{socket: s, reservation: reservation.reservation})
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

// unmarkedSCION reports once that SCION sockets are left unmarked.
var unmarkedSCION sync.Once

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
	capacity     int
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
	if capacity < 0 {
		capacity = 0
	}
	return &SCIONConnRegistry{conns: make(map[string]*scionEntry, capacity), capacity: capacity}
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
	if len(r.conns) >= r.capacity {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: SCION connection capacity", ErrQuota)
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
	// pan opens the socket inside DialUDP and exposes neither it nor a hook
	// to set socket options on it, so a SCION socket cannot be marked: its
	// packets are not attributed to the run by the eBPF tagger. SCION is
	// therefore labelled untagged rather than refused: the capability report
	// and the result's vantage point carry tagging.scion = none. The gap is
	// also logged once per process rather than skipped silently.
	if pktTagger != nil {
		unmarkedSCION.Do(func() {
			sugar.Warnw("SCION sockets cannot be marked; their packets are not attributed to the run (tagging.scion = none)", "udpAddr", udpAddr)
		})
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
