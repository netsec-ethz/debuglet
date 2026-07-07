package hostconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/ratelimit/ebpf"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

type HostConn struct {
	pc    *ebpf.PacketCount
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
	ConnectionAddr   string
}

func NewConnection(ctx context.Context, pc *ebpf.PacketCount, id uuid.UUID, conn net.Conn, opts HostConnOpts) (*HostConn, error) {
	if pc == nil {
		return nil, errors.New("received <nil> PacketCount")
	}

	hn := &HostConn{
		pc:         pc,
		id:         id,
		limit:      opts.MaximumBandwidth,
		connCtx:    ctx,
		socketType: opts.SocketType,
		conn:       conn,
		connAddr:   opts.ConnectionAddr,
	}

	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("connection does not implement syscall.Conn")
	}
	socketID, err := hn.pc.Attach(sc, hn.id)
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}
	hn.socketID = socketID

	for _, ip := range opts.AllowedAddresses {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			fmt.Printf("Failed to parse IP %s: %v\n", ip, err)
			continue
		}
		err = hn.pc.SetLimit(addr, hn.id, hn.limit)
		if err != nil {
			fmt.Printf("Failed to set limit for IP %s: %v\n", ip, err)
		}
	}

	return hn, nil
}

func (h *HostConn) Drain(ctx context.Context) {
	tcpConn, ok := h.conn.(*net.TCPConn)
	if !ok {
		return
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return
	}
	for {
		var (
			info *unix.TCPInfo
			err  error
		)
		rawConn.Control(func(fd uintptr) {
			info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		})

		if err != nil || info == nil || info.Notsent_bytes == 0 {
			return
		}

		estDuration := 200 * time.Millisecond
		if h.limit > 0 {
			estDuration = time.Duration(float64(info.Notsent_bytes) / float64(h.limit) * float64(time.Second))
		}
		waitFor := max(min(time.Second, estDuration/2), 10*time.Millisecond)

		select {
		case <-time.After(waitFor):
		case <-ctx.Done():
			return
		}
	}
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
	conn := h.conn
	h.conn = nil
	conn.Close()
	if h.pc != nil {
		return h.pc.Detach(h.socketID)
	}
	return nil
}

func (h *HostConn) Write(message []byte) (int, error) { return h.conn.Write(message) }
func (h *HostConn) Read(buffer []byte) (int, error)   { return h.conn.Read(buffer) }
func (h *HostConn) Type() socket.SocketType           { return h.socketType }
func (h *HostConn) ConnectionAddr() string            { return h.connAddr }

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
