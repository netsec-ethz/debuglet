// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm/hostconn"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"net"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
)

type WasmEnv struct {
	mu           sync.Mutex
	closed       bool
	closeOnce    sync.Once
	closeErr     error
	lateCloseErr error

	DebugletID uuid.UUID
	Policy     scheduler.Policy
	// Net is the network policy every transport is checked against. It is the
	// operator's rules and this run's declared destinations together; without
	// it no transport is available.
	Net *netpolicy.Policy

	Limiter     *app.Limiter
	PacketCount ratelimit.PacketCount
	// Accountant covers the traffic no connection wrapper does: listener
	// datagrams and SCION packets.
	Accountant   *ratelimit.Accountant
	LastReceived net.Addr
	Logger       *zap.SugaredLogger
	TlsCfg       *tls.Config
	Tagger       tagger.TaggerInterface
	// untaggedOnce reports once per run that a datagram connection is sent
	// untagged by the pure-Go tagger.
	untaggedOnce sync.Once

	// Listeners
	PortManager *socket.PortManager
	// TCP
	TcpServer     *net.TCPListener
	TcpServerPort int
	TcpServerAddr string
	// UDP
	UdpServer     *net.UDPConn
	UdpServerPort int
	UdpServerAddr string

	ScionServer pan.ListenConn

	Budget                                           *socket.Budget
	tcpReservation, udpReservation, scionReservation *socket.Reservation
	Registry                                         *socket.SocketRegistry
	ScionConn                                        *socket.SCIONConnRegistry
}

// warnPrivate keeps per-run host failures correlated without putting raw
// network/library diagnostics in the routine log. Event names are fixed here.
func (e *WasmEnv) warnPrivate(event string, diagnostic error) {
	e.Logger.Warnw(event, "debugletID", e.DebugletID.String())
	e.Logger.Debugw("Private guest host diagnostic", "event", event, "debugletID", e.DebugletID.String(),
		"error", daemonlog.Diagnostic(diagnostic))
}

// DatagramTagger is the pure-Go tagger, which tags UDP and ICMP by sending
// them itself; the eBPF tagger tags every socket in the kernel instead.
type DatagramTagger interface {
	WrapDatagram(net.Conn) (net.Conn, error)
}

// tagDatagrams returns conn wrapped so its datagrams leave tagged, when the
// run's tagger is the pure-Go one and conn is a UDP or ICMP connection. A
// connection it cannot wrap is returned as it is and sent untagged.
func tagDatagrams(e *WasmEnv, conn net.Conn, socketType socket.SocketType) net.Conn {
	datagrams, ok := e.Tagger.(DatagramTagger)
	if !ok || (socketType != socket.SocketTypeUDP && socketType != socket.SocketTypeICMP4) {
		return conn
	}
	wrapped, err := datagrams.WrapDatagram(conn)
	if err != nil {
		e.untaggedOnce.Do(func() {
			e.warnPrivate("Datagrams of this run leave untagged", fmt.Errorf("remote %s: %w", conn.RemoteAddr(), err))
		})
		return conn
	}
	return wrapped
}

// markSocket puts conn under this run's packet attribution. Without a tagger
// there is nothing to mark.
func markSocket(e *WasmEnv, conn syscall.Conn) error {
	if e.Tagger == nil {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("mark socket: %w", err)
	}
	return hostconn.MarkSocket(raw, e.Tagger)
}

// Listener publication competes with terminal closure. References remain
// immutable after successful publication; late resources are consumed/closed.
// A listener arrives already marked: the PortManager marks it in its listen
// control hook, before the socket is bound and listening, so no handshake
// reply or datagram leaves it unattributed.
func (e *WasmEnv) InstallTCP(lis *net.TCPListener, port int, addr string, reservation *socket.Reservation) error {
	e.mu.Lock()
	if e.closed || e.TcpServer != nil {
		e.mu.Unlock()
		err := lis.Close()
		reservation.Release()
		if e.PortManager != nil {
			e.PortManager.Release(port)
		}
		e.RecordCleanupError(err)
		return errors.Join(net.ErrClosed, err)
	}
	e.TcpServer, e.TcpServerPort, e.TcpServerAddr = lis, port, addr
	e.tcpReservation = reservation
	e.mu.Unlock()
	return nil
}
func (e *WasmEnv) InstallUDP(conn *net.UDPConn, port int, addr string, reservation *socket.Reservation) error {
	e.mu.Lock()
	if e.closed || e.UdpServer != nil {
		e.mu.Unlock()
		err := conn.Close()
		reservation.Release()
		if e.PortManager != nil {
			e.PortManager.Release(port)
		}
		e.RecordCleanupError(err)
		return errors.Join(net.ErrClosed, err)
	}
	e.UdpServer, e.UdpServerPort, e.UdpServerAddr = conn, port, addr
	e.udpReservation = reservation
	e.mu.Unlock()
	return nil
}
func (e *WasmEnv) InstallSCION(conn pan.ListenConn, reservation *socket.Reservation) error {
	e.mu.Lock()
	if e.closed || e.ScionServer != nil {
		e.mu.Unlock()
		err := conn.Close()
		reservation.Release()
		e.RecordCleanupError(err)
		return errors.Join(net.ErrClosed, err)
	}
	e.ScionServer = conn
	e.scionReservation = reservation
	e.mu.Unlock()
	return nil
}
func (e *WasmEnv) SCIONAddr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ScionServer == nil {
		return ""
	}
	return e.ScionServer.LocalAddr().String()
}

func (e *WasmEnv) Close() error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		tcp, tcpPort := e.TcpServer, e.TcpServerPort
		udp, udpPort := e.UdpServer, e.UdpServerPort
		scion := e.ScionServer
		e.mu.Unlock()
		if tcp != nil {
			e.closeErr = errors.Join(e.closeErr, tcp.Close())
			e.tcpReservation.Release()
			if e.PortManager != nil {
				e.PortManager.Release(tcpPort)
			}
		}
		if udp != nil {
			e.closeErr = errors.Join(e.closeErr, udp.Close())
			e.udpReservation.Release()
			if e.PortManager != nil {
				e.PortManager.Release(udpPort)
			}
		}
		if scion != nil {
			e.closeErr = errors.Join(e.closeErr, scion.Close())
			e.scionReservation.Release()
		}
		if e.Registry != nil {
			_ = e.Registry.CloseAll()
		}
		if e.ScionConn != nil {
			_ = e.ScionConn.CloseAll()
		}
		if e.Tagger != nil {
			e.closeErr = errors.Join(e.closeErr, e.Tagger.Close())
		}
	})
	// Producers may complete after the I/O watcher. Its final caller invokes
	// Close again after those producers join to obtain their late close errors.
	e.mu.Lock()
	lateErr := e.lateCloseErr
	e.mu.Unlock()
	var registryErr error
	if e.Registry != nil {
		registryErr = e.Registry.CloseAll()
	}
	var scionErr error
	if e.ScionConn != nil {
		scionErr = e.ScionConn.CloseAll()
	}
	return errors.Join(e.closeErr, registryErr, scionErr, lateErr)
}

// RecordCleanupError records a resource-release failure independently of the
// operation's selected execution/cancellation outcome. Nil is a no-op.
func (e *WasmEnv) RecordCleanupError(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.lateCloseErr = errors.Join(e.lateCloseErr, err)
	e.mu.Unlock()
}
