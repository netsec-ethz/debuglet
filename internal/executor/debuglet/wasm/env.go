package wasm

import (
	"crypto/tls"
	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/ratelimit"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/scheduler"
	"debuglet/internal/executor/tagger"
	"net"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
)

type WasmEnv struct {
	DebugletID string
	Policy     scheduler.Policy

	Limiter         *app.Limiter
	PacketCount     ratelimit.PacketCount
	LastReceived    net.Addr
	Logger          *zap.SugaredLogger
	TlsCfg          *tls.Config
	Tagger          tagger.TaggerInterface

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

	IpServer    net.PacketConn
	ScionServer pan.ListenConn

	Registry  *socket.SocketRegistry
	ScionConn *socket.SCIONConnRegistry
}

func (e *WasmEnv) Close() {
	e.Registry.CloseAll()
	if e.ScionServer != nil {
		e.ScionServer.Close()
	}
	if e.UdpServer != nil {
		e.UdpServer.Close()
		if e.PortManager != nil {
			e.PortManager.Release(e.UdpServerPort)
		}
	}
	if e.TcpServer != nil {
		e.TcpServer.Close()
		if e.PortManager != nil {
			e.PortManager.Release(e.TcpServerPort)
		}
	}
	if e.IpServer != nil {
		e.IpServer.Close()
	}
	if e.Tagger != nil {
		e.Tagger.Close()
	}
}
