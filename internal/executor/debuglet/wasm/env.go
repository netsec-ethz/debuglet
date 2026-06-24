package wasm

import (
	"crypto/tls"
	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/transport/rpc"
	"debuglet/internal/executor/tagger"
	"net"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
)

type WasmEnv struct {
	DebugletID string
	Policy     rpc.Policy

	Limiter      *app.Limiter
	LastReceived net.Addr
	Logger       *zap.SugaredLogger
	TlsCfg       *tls.Config
	Tagger       tagger.TaggerInterface

	TcpServer   *net.TCPListener
	UdpServer   net.PacketConn
	IpServer    net.Listener
	ScionServer pan.ListenConn

	Registry  *socket.SocketRegistry
	ScionConn *socket.SCIONConnRegistry
}

func (e *WasmEnv) Close() {
	if e.ScionServer != nil {
		e.ScionServer.Close()
	}
	if e.UdpServer != nil {
		e.UdpServer.Close()
	}
	if e.TcpServer != nil {
		e.TcpServer.Close()
	}
	if e.IpServer != nil {
		e.IpServer.Close()
	}
	if e.Tagger != nil {
		e.Tagger.Close()
	}
}
