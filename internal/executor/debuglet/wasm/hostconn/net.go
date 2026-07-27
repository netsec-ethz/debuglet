package hostconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/ratelimit"
	"debuglet/internal/executor/ratelimit/app"

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

func NewConnection(ctx context.Context, pc ratelimit.PacketCount, id uuid.UUID, conn net.Conn, opts HostConnOpts) (*HostConn, error) {
	if pc == nil {
		return nil, errors.New("received <nil> PacketCount")
	}

	hc := &HostConn{
		pc:         pc,
		id:         id,
		limit:      opts.MaximumBandwidth,
		connCtx:    ctx,
		socketType: opts.SocketType,
	}

	conn, err := hc.pc.Attach(conn, hc.id, opts.ConnAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}
	hc.conn = conn

	if err := hc.pc.SetLimit(opts.ConnAddr, hc.id, hc.limit); err != nil {
		return nil, fmt.Errorf("failed to set limit: %w", err)
	}

	return hc, nil
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
	h.conn.Close()
	h.conn = nil
	return nil
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
