// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package hostconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"

	"github.com/google/uuid"
)

type HostConn struct {
	pc    ratelimit.PacketCount
	id    uuid.UUID
	limit app.Bitrate

	conn       net.Conn
	connCtx    context.Context
	socketID   uint32
	socketType socket.SocketType

	closeOnce sync.Once
	closeErr  error
}

type HostConnOpts struct {
	ConnAddr         string
	MaximumBandwidth app.Bitrate
	SocketType       socket.SocketType
}

// cleanupError distinguishes connection release failure from attach/limit
// failure without exposing a new guest ABI or conflating execution and cleanup.
type cleanupError struct{ err error }

func (e *cleanupError) Error() string { return e.err.Error() }
func (e *cleanupError) Unwrap() error { return e.err }
func CleanupError(err error) error {
	var cleanup *cleanupError
	if errors.As(err, &cleanup) {
		return cleanup.err
	}
	return nil
}

// NewConnection consumes conn. On failure it closes the attached wrapper (if
// available), otherwise the original connection. On success HostConn owns it.
func NewConnection(ctx context.Context, pc ratelimit.PacketCount, id uuid.UUID, conn net.Conn, opts HostConnOpts) (_ *HostConn, err error) {
	if conn == nil {
		return nil, errors.New("received <nil> connection")
	}
	owned := conn
	defer func() {
		if err != nil {
			if closeErr := owned.Close(); closeErr != nil {
				err = errors.Join(err, &cleanupError{closeErr})
			}
		}
	}()
	if pc == nil {
		return nil, errors.New("received <nil> PacketCount")
	}
	attached, err := pc.Attach(conn, id, opts.ConnAddr)
	if attached != nil {
		owned = attached
	}
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}
	if attached == nil {
		return nil, errors.New("attach returned <nil> connection")
	}
	if err := pc.SetLimit(opts.ConnAddr, id, opts.MaximumBandwidth); err != nil {
		return nil, fmt.Errorf("failed to set limit: %w", err)
	}
	return &HostConn{pc: pc, id: id, limit: opts.MaximumBandwidth, connCtx: ctx, socketType: opts.SocketType, conn: attached}, nil
}

func (h *HostConn) Close() error {
	h.closeOnce.Do(func() {
		h.closeErr = h.closeImpl()
	})
	return h.closeErr
}

func (h *HostConn) closeImpl() error {
	if h.conn == nil {
		return nil
	}
	return h.conn.Close()
}

func (h *HostConn) Write(b []byte) (int, error) { return h.conn.Write(b) }
func (h *HostConn) Read(b []byte) (int, error)  { return h.conn.Read(b) }
func (h *HostConn) Type() socket.SocketType     { return h.socketType }

func (h *HostConn) Addr() string {
	host, _, err := net.SplitHostPort(h.conn.RemoteAddr().String())
	if err != nil {
		return h.conn.RemoteAddr().String()
	}
	return host
}

func (h *HostConn) RemoteAddr() string { return h.conn.RemoteAddr().String() }
