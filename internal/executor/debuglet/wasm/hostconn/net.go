package hostconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/debuglet/socket/netutil"
	"debuglet/internal/executor/ratelimit"
	"debuglet/internal/executor/ratelimit/app"

	"github.com/google/uuid"
)

type HostConn struct {
	pc    ratelimit.PacketCount
	id    uuid.UUID
	limit app.Bitrate

	conn       net.Conn
	connAddr   string
	connCtx    context.Context
	socketID   uint32
	socketType socket.SocketType

	closeOnce sync.Once
	closeErr  error
}

type HostConnOpts struct {
	AllowedAddresses []string
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

	conn, err := hc.pc.Attach(conn, hc.id)
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}
	hc.conn = conn

	for _, ip := range opts.AllowedAddresses {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			fmt.Printf("Failed to parse IP %s: %v\n", ip, err)
			continue
		}
		err = hc.pc.SetLimit(netutil.ToIPv6(addr), hc.id, hc.limit)
		if err != nil {
			fmt.Printf("Failed to set limit for IP %s: %v\n", ip, err)
		}
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

func (h *HostConn) RemoteIP() netip.Addr {
	host, _, _ := net.SplitHostPort(h.conn.RemoteAddr().String())
	addr, _ := netip.ParseAddr(host)
	return addr
}
