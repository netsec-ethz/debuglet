// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package wasm contains the WASM host function implementations that are
// imported by WASM modules at runtime. Each host function follows the wazero
// calling convention: (ctx context.Context, mod api.Module, params []uint64) →
// []uint64.
//
// Go function names use camelCase with a "host" prefix. The WASM-visible
// import key strings (used during host module registration) are left unchanged so
// that existing WASM modules do not need recompilation.
package wasm

import (
	"context"
	"crypto/tls"
	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/ratelimit/app"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/tetratelabs/wazero/api"
)

// =============================================================================
// Generic socket API
// =============================================================================

// HostConnect dials a IP/UDP/TCP(+TLS) connection to addresses[index] and registers
// it in the SocketRegistry. Returns the socket handle as I32.
// WASM key: "connect_tcp", "connect_ip", "connect_udp", "connect_tls"
func HostConnect(env *WasmEnv, socketType socket.SocketType) func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
	var network string
	switch socketType {
	case socket.SocketTypeTLS:
		network = "tcp"
	case socket.SocketTypeICMP4:
		network = "ip4:icmp"
	case socket.SocketTypeTCP:
		network = "tcp"
	case socket.SocketTypeUDP:
		network = "udp"
	default:
		panic(fmt.Errorf("connect: unknown SocketType %d", socketType))
	}

	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
		addr, err := ExtractStr(mod, addrp, addrLen)

		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
		}

		if env.Tagger != nil {
			dialer.Control = func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					env.Tagger.SetSocketMark(int(fd))
				})
			}
		}

		var conn net.Conn
		if socketType == socket.SocketTypeTLS {
			conn, err = tls.DialWithDialer(dialer, "tcp", addr, env.TlsCfg)
		} else {
			conn, err = dialer.DialContext(ctx, network, addr)
		}

		if err != nil {
			env.Logger.Warnw("hostConnect: failed to dial", "addr", addr, "err", err)
			return -1
		}

		sock := socket.NewGenericSocket(conn, socketType, addr)
		return env.Registry.Add(sock)
	}
}

// HostReceiveData reads up to size bytes from the socket at sockID into
// the buffer at pointer ptr. Returns the number of bytes read as I32.
// WASM key: "receive_tcp_data", "receive_ip_data"
func HostReceiveData(env *WasmEnv) func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) int32 {
		if int64(bufLen)*8 > env.Policy.FloorBW {
			panic(fmt.Errorf("buffer length (%d bytes) can't be greater than the floor bandwidth (%d bits)", bufLen, env.Policy.FloorBW))
		}

		sock, err := env.Registry.Get(sockID)
		if err != nil {
			env.Logger.Warnw("hostReceiveData: invalid handle", "handle", sockID, "err", err)
			panic(fmt.Errorf("receive_data: %w", err))
		}

		buf, err := ExtractMem[byte](mod, bufp, bufLen)
		if err != nil {
			panic(err)
		}

		// NOTE: ratelimiting is done using the BUFFER SIZE, not actual received size.
		if err := ratelimit(ctx, env, app.TransferIn, sock.Addr(), app.Bitrate(len(buf))*app.Byte); err != nil {
			panic(fmt.Errorf("failed to ratelimit: %w", err))
		}

		n, err := sock.Read(buf)
		if err != nil {
			env.Logger.Warnw("hostReceiveData: read error", "err", err)
			panic(fmt.Errorf("receive_data: read error: %w", err))
		}

		return int32(n)
	}
}

// HostSendData writes size bytes starting at offset ptr from the WASM
// memory to the socket at sockID.
// WASM key: "send_tcp_data", "send_icmp4_data"
func HostSendData(env *WasmEnv) func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) {
	return func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) {
		if int64(bufLen)*8 > env.Policy.FloorBW {
			panic(fmt.Errorf("buffer length (%d bytes) can't be greater than the floor bandwidth (%d bits)", bufLen, env.Policy.FloorBW))
		}

		sock, err := env.Registry.Get(sockID)
		if err != nil {
			env.Logger.Warnw("hostSendData: invalid handle", "handle", sockID, "err", err)
			panic(fmt.Errorf("send_data: %w", err))
		}

		message, err := ExtractMem[byte](mod, bufp, bufLen)
		if err != nil {
			panic(err)
		}
		env.Logger.Debugw("hostSendData: sending message", "len", len(message))

		if err := ratelimit(ctx, env, app.TransferOut, sock.Addr(), app.Bitrate(len(message))*app.Byte); err != nil {
			panic(fmt.Errorf("failed to ratelimit: %w", err))
		}

		if _, err = sock.Write(message); err != nil {
			env.Logger.Warnw("hostSendData: write error", "err", err)
			panic(fmt.Errorf("send_data: write error: %w", err))
		}
	}
}

// HostClose closes the socket at handle sockID.
// WASM key: "close_tcp", "close_ip"
func HostClose(env *WasmEnv) func(ctx context.Context, sockID int32) {
	return func(ctx context.Context, sockID int32) {
		if err := env.Registry.Close(sockID); err != nil {
			env.Logger.Warnw("hostClose: close error", "handle", sockID, "err", err)
			panic(fmt.Errorf("close_tcp: %w", err))
		}
	}
}

// =============================================================================
// TCP socket API
// =============================================================================

// HostAcceptTCP accepts one incoming TCP connection on the server and registers
// it in the SocketRegistry. Returns the socket handle as I32.
// WASM key: "accept_tcp"
func HostAcceptTCP(env *WasmEnv) func(ctx context.Context) int32 {
	return func(ctx context.Context) int32 {
		conn, err := env.TcpServer.AcceptTCP()
		if err != nil {
			env.Logger.Warnw("hostAcceptTCP: failed to accept", "err", err)
			panic(fmt.Errorf("accept_tcp: %w", err))
		}

		return env.Registry.Add(socket.NewGenericSocket(conn, socket.SocketTypeTCP, ""))
	}
}

// =============================================================================
// IP socket API
// WASM keys: "connect_ip", "accept_ip", "receive_ip_data",
//
//	"send_ip_data", "close_ip"
//
// =============================================================================

// HostAcceptIP accepts one incoming IP connection on the server and registers
// it in the SocketRegistry. Returns the socket handle as I32.
// WASM key: "accept_ip"
func HostAcceptIP(env *WasmEnv) func() int32 {
	return func() int32 {
		conn, err := env.IpServer.Accept()
		if err != nil {
			env.Logger.Warnw("hostAcceptIP: failed to accept", "err", err)
			panic(fmt.Errorf("accept_ip: %w", err))
		}

		ipConn, ok := conn.(*net.IPConn)
		if !ok {
			panic(fmt.Errorf("accept_ip: expected *net.IPConn, got %T", conn))
		}

		return env.Registry.Add(socket.NewGenericSocket(ipConn, socket.SocketTypeICMP4, ""))
	}
}

// =============================================================================
// SCION-UDP API
// WASM keys: "send_scion_udp_packet", "receive_scion_server_udp_packet",
//
//	"scion_available_paths", "scion_path_length",
//	"scion_get_interface_details", "scion_select_path"
//
// =============================================================================

// HostSendSCIONUDPPacket dials (or reuses) a SCION connection to
// addresses[addrIdx] and writes size bytes from udp_send_buffer.
// Returns the send timestamp as I64.
// WASM key: "send_scion_udp_packet"
func HostSendSCIONUDPPacket(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}

		sc, err := env.ScionConn.GetOrDial(ctx, addr, env.Logger, env.Tagger)
		if err != nil {
			env.Logger.Warnw("hostSendSCIONUDPPacket: dial failed", "err", err)
			panic(fmt.Errorf("send_scion_udp_packet: %w", err))
		}

		data, err := ExtractMem[byte](mod, sendp, sendLen)
		if err != nil {
			env.Logger.Warnw("hostSendSCIONUDPPacket: failed to extract buffer", "err", err)
			panic(fmt.Errorf("send_scion_udp_packet: failed to extract udp_send_buffer: %w", err))
		}

		deadline, ok := ctx.Deadline()
		if !ok {
			panic(fmt.Errorf("send_scion_udp_packet: debuglet has no deadline"))
		}
		(*sc.Conn).SetDeadline(deadline)

		if _, err = (*sc.Conn).Write(data); err != nil {
			env.Logger.Warnw("hostSendSCIONUDPPacket: write failed", "err", err)
			panic(fmt.Errorf("send_scion_udp_packet: write failed: %w", err))
		}
		return time.Now().UnixNano()
	}
}

// HostReceiveSCIONServerUDPPacket reads one packet from the SCION server
// listener into udp_receive_buffer. timeout is the deadline in milliseconds.
// Returns (bytesRead I32, timestamp I64). lastReceived is updated in place.
// WASM key: "receive_scion_server_udp_packet"
func HostReceiveSCIONServerUDPPacket(env *WasmEnv) func(ctx context.Context, mod api.Module, recvp, recvLen uint32, timeout int32) (int32, int64) {
	return func(ctx context.Context, mod api.Module, recvp, recvLen uint32, timeout int32) (int32, int64) {
		buf, err := ExtractMem[byte](mod, recvp, recvLen)
		if err != nil {
			env.Logger.Warnw("hostReceiveSCIONServerUDPPacket: failed to extract buffer", "err", err)
			panic(fmt.Errorf("receive_scion_server_udp_packet: failed to extract udp_receive_buffer: %w", err))
		}

		deadline := time.Now().Add(time.Duration(timeout) * time.Millisecond)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}

		if err = env.ScionServer.SetReadDeadline(deadline); err != nil {
			env.Logger.Warnw("hostReceiveSCIONServerUDPPacket: failed to set deadline", "err", err)
			panic(fmt.Errorf("receive_scion_server_udp_packet: failed to set read deadline: %w", err))
		}

		n, from, err := env.ScionServer.ReadFrom(buf)
		if err != nil {
			env.Logger.Warnw("hostReceiveSCIONServerUDPPacket: read error", "err", err, "n", n)
			env.LastReceived = nil
			return 0, time.Now().UnixNano()
		}
		env.LastReceived = from
		return int32(n), time.Now().UnixNano()
	}
}

// HostAnswerSCIONUDPPacket replies to the last received SCION packet, or falls
// back to dialling addresses[addrIdx] if no packet has been received yet.
// WASM key: "answer_scion_udp_packet"
func HostAnswerSCIONUDPPacket(env *WasmEnv, addresses []string) func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
		data, err := ExtractMem[byte](mod, sendp, sendLen)
		if err != nil {
			env.Logger.Warnw("hostAnswerSCIONUDPPacket: failed to extract buffer", "err", err)
			return 0
		}

		if env.LastReceived != nil {
			lastReceivedAddr, ok := env.LastReceived.(pan.UDPAddr)
			if !ok {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: could not cast lastReceived to UDPAddr", "addr", env.LastReceived)
				return 0
			}

			// Match port from known addresses
			for _, addr := range addresses {
				known, err := pan.ParseUDPAddr(addr)
				if err != nil {
					continue
				}
				if known.IA == lastReceivedAddr.IA && known.IP.Compare(lastReceivedAddr.IP) == 0 {
					env.Logger.Debugw("hostAnswerSCIONUDPPacket: matched known address", "port", known.Port)
					lastReceivedAddr = lastReceivedAddr.WithPort(known.Port)
					break
				}
			}

			env.Logger.Debugw("hostAnswerSCIONUDPPacket: writing", "dst", lastReceivedAddr)
			if _, err = env.ScionServer.WriteTo(data, lastReceivedAddr); err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: write failed", "err", err)
				return 0
			}
		} else {
			env.Logger.Warnln("hostAnswerSCIONUDPPacket: lastReceived is nil, falling back to dial")
			addr, err := ExtractStr(mod, addrp, addrLen)
			if err != nil {
				panic(err)
			}
			sc, err := env.ScionConn.GetOrDial(ctx, addr, env.Logger, env.Tagger)
			if err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: dial failed", "err", err)
				panic(fmt.Errorf("answer_scion_udp_packet: %w", err))
			}
			if _, err = (*sc.Conn).Write(data); err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: write failed", "err", err)
				return 0
			}
		}
		return time.Now().UnixNano()
	}
}

// HostSCIONAvailablePaths returns the number of available SCION paths to
// addresses[addrIdx].
// WASM key: "scion_available_paths"
func HostSCIONAvailablePaths(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, err := env.ScionConn.GetOrDial(ctx, addr, env.Logger, env.Tagger)
		if err != nil {
			env.Logger.Warnw("hostSCIONAvailablePaths: dial failed", "err", err)
			panic(fmt.Errorf("scion_available_paths: %w", err))
		}

		return int32(len(sc.Selector.Paths()))
	}
}

// HostSCIONPathLength returns the hop count of path at index pathIdx for
// the connection to addresses[addrIdx].
// WASM key: "scion_path_length"
func HostSCIONPathLength(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) int32 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) int32 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, err := env.ScionConn.GetOrDial(ctx, addr, env.Logger, env.Tagger)
		if err != nil {
			env.Logger.Warnw("hostSCIONPathLength: dial failed", "err", err)
			panic(fmt.Errorf("scion_path_length: %w", err))
		}

		paths := sc.Selector.Paths()
		hops := len(paths[pathIdx].Metadata.Interfaces) / 2
		return int32(hops)
	}
}

// HostSCIONGetInterfaceDetails returns the IA and IfID of interface ifIdx
// on path pathIdx for the connection to addresses[addrIdx].
// WASM key: "scion_get_interface_details"
func HostSCIONGetInterfaceDetails(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64) {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64) {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, err := env.ScionConn.GetOrDial(ctx, addr, env.Logger, env.Tagger)
		if err != nil {
			env.Logger.Warnw("hostSCIONGetInterfaceDetails: dial failed", "err", err)
			panic(fmt.Errorf("scion_get_interface_details: %w", err))
		}

		paths := sc.Selector.Paths()

		env.Logger.Debugw("hostSCIONGetInterfaceDetails", "path", pathIdx, "interface", ifIdx)

		if int(pathIdx) >= len(paths) || int(ifIdx) >= len(paths[pathIdx].Metadata.Interfaces) {
			return 0, 0
		}

		iface := paths[pathIdx].Metadata.Interfaces[ifIdx]
		return int64(iface.IA), int64(iface.IfID)
	}
}

// HostSCIONSelectPath forces the path selector for addresses[addrIdx] to use
// path index pathIdx.
// WASM key: "scion_select_path"
func HostSCIONSelectPath(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, err := env.ScionConn.GetOrDial(ctx, addr, env.Logger, env.Tagger)
		if err != nil {
			env.Logger.Warnw("hostSCIONSelectPath: dial failed", "err", err)
			panic(fmt.Errorf("scion_select_path: %w", err))
		}

		env.Logger.Debugw("hostSCIONSelectPath: forcing path", "index", pathIdx)
		sc.Selector.ForcePath(int(pathIdx))
		env.Logger.Debugw("hostSCIONSelectPath: path selected", "path", sc.Selector.Path())
	}
}
