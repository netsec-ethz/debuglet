// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"crypto/tls"
	"errors"
	"fmt"
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

	Registry  *socket.SocketRegistry
	ScionConn *socket.SCIONConnRegistry
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
// A listener is marked before it is published, and never after closure; one
// that cannot be marked is closed. Handshake replies sent between listen and
// marking can still escape attribution.
func (e *WasmEnv) InstallTCP(lis *net.TCPListener, port int, addr string) error {
	e.mu.Lock()
	var markErr error
	if !e.closed && e.TcpServer == nil {
		markErr = markSocket(e, lis)
	}
	if markErr != nil || e.closed || e.TcpServer != nil {
		e.mu.Unlock()
		err := lis.Close()
		if e.PortManager != nil {
			e.PortManager.Release(port)
		}
		e.RecordCleanupError(err)
		if markErr != nil {
			return errors.Join(markErr, err)
		}
		return errors.Join(net.ErrClosed, err)
	}
	e.TcpServer, e.TcpServerPort, e.TcpServerAddr = lis, port, addr
	e.mu.Unlock()
	return nil
}
func (e *WasmEnv) InstallUDP(conn *net.UDPConn, port int, addr string) error {
	e.mu.Lock()
	var markErr error
	if !e.closed && e.UdpServer == nil {
		markErr = markSocket(e, conn)
	}
	if markErr != nil || e.closed || e.UdpServer != nil {
		e.mu.Unlock()
		err := conn.Close()
		if e.PortManager != nil {
			e.PortManager.Release(port)
		}
		e.RecordCleanupError(err)
		if markErr != nil {
			return errors.Join(markErr, err)
		}
		return errors.Join(net.ErrClosed, err)
	}
	e.UdpServer, e.UdpServerPort, e.UdpServerAddr = conn, port, addr
	e.mu.Unlock()
	return nil
}
func (e *WasmEnv) InstallSCION(conn pan.ListenConn) error {
	e.mu.Lock()
	if e.closed || e.ScionServer != nil {
		e.mu.Unlock()
		err := conn.Close()
		e.RecordCleanupError(err)
		return errors.Join(net.ErrClosed, err)
	}
	e.ScionServer = conn
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
			if e.PortManager != nil {
				e.PortManager.Release(tcpPort)
			}
		}
		if udp != nil {
			e.closeErr = errors.Join(e.closeErr, udp.Close())
			if e.PortManager != nil {
				e.PortManager.Release(udpPort)
			}
		}
		if scion != nil {
			e.closeErr = errors.Join(e.closeErr, scion.Close())
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
