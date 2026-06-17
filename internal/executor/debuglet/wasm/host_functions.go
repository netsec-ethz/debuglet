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
	"debuglet/pkg/tagger"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/tetratelabs/wazero/api"
	"go.uber.org/zap"
)

// =============================================================================
// Generic socket API
// =============================================================================

// HostConnect dials a IP/UDP/TCP(+TLS) connection to addresses[index] and registers
// it in the SocketRegistry. Returns the socket handle as I32.
// WASM key: "connect_tcp", "connect_ip", "connect_udp", "connect_tls"
func HostConnect(
	socketType socket.SocketType,
	sugar *zap.SugaredLogger,
	registry socket.ISocketRegistry,
	tlsCfg *tls.Config,
	pktTagger tagger.TaggerInterface,
) func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
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

		if pktTagger != nil {
			dialer.Control = func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					pktTagger.SetSocketMark(int(fd))
				})
			}
		}

		var conn net.Conn
		if socketType == socket.SocketTypeTLS {
			conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		} else {
			conn, err = dialer.DialContext(ctx, network, addr)
		}

		if err != nil {
			sugar.Warnw("hostConnect: failed to dial", "addr", addr, "err", err)
			return -1
		}

		sock := socket.NewGenericSocket(conn, socketType)
		return registry.Add(sock)
	}
}

// HostReceiveData reads up to size bytes from the socket at sockID into
// the buffer at pointer ptr. Returns the number of bytes read as I32.
// WASM key: "receive_tcp_data", "receive_ip_data"
func HostReceiveData(
	sugar *zap.SugaredLogger,
	registry socket.ISocketRegistry,
) func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) int32 {
		sock, err := registry.Get(sockID)
		if err != nil {
			sugar.Warnw("hostReceiveData: invalid handle", "handle", sockID, "err", err)
			panic(fmt.Errorf("receive_data: %w", err))
		}

		buf, err := ExtractMem[byte](mod, bufp, bufLen)
		if err != nil {
			panic(err)
		}

		n, err := sock.Read(buf)
		if err != nil {
			sugar.Warnw("hostReceiveData: read error", "err", err)
			panic(fmt.Errorf("receive_data: read error: %w", err))
		}
		return int32(n)
	}
}

// HostSendData writes size bytes starting at offset ptr from the WASM
// memory to the socket at sockID.
// WASM key: "send_tcp_data", "send_icmp4_data"
func HostSendData(
	sugar *zap.SugaredLogger,
	registry socket.ISocketRegistry,
) func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) {
	return func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) {
		sock, err := registry.Get(sockID)
		if err != nil {
			sugar.Warnw("hostSendData: invalid handle", "handle", sockID, "err", err)
			panic(fmt.Errorf("send_data: %w", err))
		}

		message, err := ExtractMem[byte](mod, bufp, bufLen)
		if err != nil {
			panic(err)
		}

		sugar.Debugw("hostSendData: sending message", "message", string(message))

		if _, err = sock.Write(message); err != nil {
			sugar.Warnw("hostSendData: write error", "err", err)
			panic(fmt.Errorf("send_data: write error: %w", err))
		}
	}
}

// HostClose closes the socket at handle sockID.
// WASM key: "close_tcp", "close_ip"
func HostClose(
	sugar *zap.SugaredLogger,
	registry socket.ISocketRegistry,
) func(ctx context.Context, sockID int32) {
	return func(ctx context.Context, sockID int32) {
		if err := registry.Close(sockID); err != nil {
			sugar.Warnw("hostClose: close error", "handle", sockID, "err", err)
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
func HostAcceptTCP(
	tcpServer *net.TCPListener,
	sugar *zap.SugaredLogger,
	registry socket.ISocketRegistry,
) func(ctx context.Context) int32 {
	return func(ctx context.Context) int32 {
		conn, err := tcpServer.AcceptTCP()
		if err != nil {
			sugar.Warnw("hostAcceptTCP: failed to accept", "err", err)
			panic(fmt.Errorf("accept_tcp: %w", err))
		}

		return registry.Add(socket.NewGenericSocket(conn, socket.SocketTypeTCP))
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
func HostAcceptIP(
	ipServer net.Listener,
	sugar *zap.SugaredLogger,
	registry socket.ISocketRegistry,
) func() int32 {
	return func() int32 {
		conn, err := ipServer.Accept()
		if err != nil {
			sugar.Warnw("hostAcceptIP: failed to accept", "err", err)
			panic(fmt.Errorf("accept_ip: %w", err))
		}

		ipConn, ok := conn.(*net.IPConn)
		if !ok {
			panic(fmt.Errorf("accept_ip: expected *net.IPConn, got %T", conn))
		}

		return registry.Add(socket.NewGenericSocket(ipConn, socket.SocketTypeICMP4))
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
func HostSendSCIONUDPPacket(
	scionConns *socket.SCIONConnRegistry,
	sugar *zap.SugaredLogger,
	pktTagger tagger.TaggerInterface,
) func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}

		sc, err := scionConns.GetOrDial(ctx, addr, sugar, pktTagger)
		if err != nil {
			sugar.Warnw("hostSendSCIONUDPPacket: dial failed", "err", err)
			panic(fmt.Errorf("send_scion_udp_packet: %w", err))
		}

		data, err := ExtractMem[byte](mod, sendp, sendLen)
		if err != nil {
			sugar.Warnw("hostSendSCIONUDPPacket: failed to extract buffer", "err", err)
			panic(fmt.Errorf("send_scion_udp_packet: failed to extract udp_send_buffer: %w", err))
		}

		deadline, ok := ctx.Deadline()
		if !ok {
			panic(fmt.Errorf("send_scion_udp_packet: debuglet has no deadline"))
		}
		(*sc.Conn).SetDeadline(deadline)

		if _, err = (*sc.Conn).Write(data); err != nil {
			sugar.Warnw("hostSendSCIONUDPPacket: write failed", "err", err)
			panic(fmt.Errorf("send_scion_udp_packet: write failed: %w", err))
		}
		return time.Now().UnixNano()
	}
}

// HostReceiveSCIONServerUDPPacket reads one packet from the SCION server
// listener into udp_receive_buffer. timeout is the deadline in milliseconds.
// Returns (bytesRead I32, timestamp I64). lastReceived is updated in place.
// WASM key: "receive_scion_server_udp_packet"
func HostReceiveSCIONServerUDPPacket(
	lastReceived *net.Addr,
	sugar *zap.SugaredLogger,
	scionServer *pan.ListenConn,
	pktTagger tagger.TaggerInterface,
) func(ctx context.Context, mod api.Module, recvp, recvLen uint32, timeout int32) (int32, int64) {
	return func(ctx context.Context, mod api.Module, recvp, recvLen uint32, timeout int32) (int32, int64) {
		buf, err := ExtractMem[byte](mod, recvp, recvLen)
		if err != nil {
			sugar.Warnw("hostReceiveSCIONServerUDPPacket: failed to extract buffer", "err", err)
			panic(fmt.Errorf("receive_scion_server_udp_packet: failed to extract udp_receive_buffer: %w", err))
		}

		deadline := time.Now().Add(time.Duration(timeout) * time.Millisecond)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}

		if err = (*scionServer).SetReadDeadline(deadline); err != nil {
			sugar.Warnw("hostReceiveSCIONServerUDPPacket: failed to set deadline", "err", err)
			panic(fmt.Errorf("receive_scion_server_udp_packet: failed to set read deadline: %w", err))
		}

		n, from, err := (*scionServer).ReadFrom(buf)
		if err != nil {
			sugar.Warnw("hostReceiveSCIONServerUDPPacket: read error", "err", err, "n", n)
			*lastReceived = nil
			return 0, time.Now().UnixNano()
		}
		*lastReceived = from
		return int32(n), time.Now().UnixNano()
	}
}

// HostAnswerSCIONUDPPacket replies to the last received SCION packet, or falls
// back to dialling addresses[addrIdx] if no packet has been received yet.
// WASM key: "answer_scion_udp_packet"
func HostAnswerSCIONUDPPacket(
	lastReceived *net.Addr,
	scionConns *socket.SCIONConnRegistry,
	addresses []string,
	sugar *zap.SugaredLogger,
	scionServer *pan.ListenConn,
	pktTagger tagger.TaggerInterface,
) func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
		data, err := ExtractMem[byte](mod, sendp, sendLen)
		if err != nil {
			sugar.Warnw("hostAnswerSCIONUDPPacket: failed to extract buffer", "err", err)
			return 0
		}

		if lastReceived != nil && *lastReceived != nil {
			lastReceivedAddr, ok := (*lastReceived).(pan.UDPAddr)
			if !ok {
				sugar.Warnw("hostAnswerSCIONUDPPacket: could not cast lastReceived to UDPAddr", "addr", *lastReceived)
				return 0
			}

			// Match port from known addresses
			for _, addr := range addresses {
				known, err := pan.ParseUDPAddr(addr)
				if err != nil {
					continue
				}
				if known.IA == lastReceivedAddr.IA && known.IP.Compare(lastReceivedAddr.IP) == 0 {
					sugar.Debugw("hostAnswerSCIONUDPPacket: matched known address", "port", known.Port)
					lastReceivedAddr = lastReceivedAddr.WithPort(known.Port)
					break
				}
			}

			sugar.Debugw("hostAnswerSCIONUDPPacket: writing", "dst", lastReceivedAddr)
			if _, err = (*scionServer).WriteTo(data, lastReceivedAddr); err != nil {
				sugar.Warnw("hostAnswerSCIONUDPPacket: write failed", "err", err)
				return 0
			}
		} else {
			sugar.Warnln("hostAnswerSCIONUDPPacket: lastReceived is nil, falling back to dial")
			addr, err := ExtractStr(mod, addrp, addrLen)
			if err != nil {
				panic(err)
			}
			sc, err := scionConns.GetOrDial(ctx, addr, sugar, pktTagger)
			if err != nil {
				sugar.Warnw("hostAnswerSCIONUDPPacket: dial failed", "err", err)
				panic(fmt.Errorf("answer_scion_udp_packet: %w", err))
			}
			if _, err = (*sc.Conn).Write(data); err != nil {
				sugar.Warnw("hostAnswerSCIONUDPPacket: write failed", "err", err)
				return 0
			}
		}
		return time.Now().UnixNano()
	}
}

// HostSCIONAvailablePaths returns the number of available SCION paths to
// addresses[addrIdx].
// WASM key: "scion_available_paths"
func HostSCIONAvailablePaths(
	scionConns *socket.SCIONConnRegistry,
	sugar *zap.SugaredLogger,
	pktTagger tagger.TaggerInterface,
) func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, err := scionConns.GetOrDial(ctx, addr, sugar, pktTagger)
		if err != nil {
			sugar.Warnw("hostSCIONAvailablePaths: dial failed", "err", err)
			panic(fmt.Errorf("scion_available_paths: %w", err))
		}

		return int32(len(sc.Selector.Paths()))
	}
}

// HostSCIONPathLength returns the hop count of path at index pathIdx for
// the connection to addresses[addrIdx].
// WASM key: "scion_path_length"
func HostSCIONPathLength(
	scionConns *socket.SCIONConnRegistry,
	sugar *zap.SugaredLogger,
	pktTagger tagger.TaggerInterface,
) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) int32 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) int32 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, err := scionConns.GetOrDial(ctx, addr, sugar, pktTagger)
		if err != nil {
			sugar.Warnw("hostSCIONPathLength: dial failed", "err", err)
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
func HostSCIONGetInterfaceDetails(
	scionConns *socket.SCIONConnRegistry,
	sugar *zap.SugaredLogger,
	pktTagger tagger.TaggerInterface,
) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64) {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64) {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, err := scionConns.GetOrDial(ctx, addr, sugar, pktTagger)
		if err != nil {
			sugar.Warnw("hostSCIONGetInterfaceDetails: dial failed", "err", err)
			panic(fmt.Errorf("scion_get_interface_details: %w", err))
		}

		paths := sc.Selector.Paths()

		sugar.Debugw("hostSCIONGetInterfaceDetails", "path", pathIdx, "interface", ifIdx)

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
func HostSCIONSelectPath(
	scionConns *socket.SCIONConnRegistry,
	sugar *zap.SugaredLogger,
	pktTagger tagger.TaggerInterface,
) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, err := scionConns.GetOrDial(ctx, addr, sugar, pktTagger)
		if err != nil {
			sugar.Warnw("hostSCIONSelectPath: dial failed", "err", err)
			panic(fmt.Errorf("scion_select_path: %w", err))
		}

		sugar.Debugw("hostSCIONSelectPath: forcing path", "index", pathIdx)
		sc.Selector.ForcePath(int(pathIdx))
		sugar.Debugw("hostSCIONSelectPath: path selected", "path", sc.Selector.Path())
	}
}

// =============================================================================
// Debug write API
// !!! These should not be exposed to untrusted WASM modules !!!
// WASM keys: "write", "write_noeol", "write_i32", "write_i64",
//
//	"write_i32x", "write_i64x", "write_delta_timestamp"
//
// =============================================================================

// HostReadWriteBuffer is a shared helper that reads the write_buffer global
// from WASM memory. It is not exported to WASM.
func HostReadWriteBuffer(sugar *zap.SugaredLogger) func(ctx context.Context, mod api.Module, writep, writeLen uint32) ([]byte, error) {
	return func(ctx context.Context, mod api.Module, writep, writeLen uint32) ([]byte, error) {
		data, err := ExtractMem[byte](mod, writep, writeLen)
		if err != nil {
			sugar.Warnw("hostReadWriteBuffer: failed to extract buffer", "err", err)
			return nil, fmt.Errorf("write: failed to extract write_buffer: %w", err)
		}
		return data, nil
	}
}

// HostWriteString prints a UTF-8 string followed by a newline.
// WASM key: "write"
func HostWriteString(sugar *zap.SugaredLogger) func(ctx context.Context, mod api.Module, writep, writeLen uint32) {
	readBuf := HostReadWriteBuffer(sugar)
	return func(ctx context.Context, mod api.Module, writep, writeLen uint32) {
		data, err := readBuf(ctx, mod, writep, writeLen)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", data)
		sugar.Debugw("hostWriteString", "data", data)
	}
}

// HostWriteStringNoEOL prints a UTF-8 string without a trailing newline.
// WASM key: "write_noeol"
func HostWriteStringNoEOL(sugar *zap.SugaredLogger) func(ctx context.Context, mod api.Module, writep, writeLen uint32) {
	readBuf := HostReadWriteBuffer(sugar)
	return func(ctx context.Context, mod api.Module, writep, writeLen uint32) {
		data, err := readBuf(ctx, mod, writep, writeLen)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", data)
		sugar.Debugw("hostWriteStringNoEOL", "data", data)
	}
}

// HostWriteI32 prints an int32 in decimal.
// WASM key: "write_i32"
func HostWriteI32(sugar *zap.SugaredLogger) func(ctx context.Context, n int32) {
	return func(ctx context.Context, n int32) {
		fmt.Printf("%d", n)
		sugar.Debugw("hostWriteI32", "value", n)
	}
}

// HostWriteI64 prints an int64 in decimal.
// WASM key: "write_i64"
func HostWriteI64(sugar *zap.SugaredLogger) func(ctx context.Context, n int64) {
	return func(ctx context.Context, n int64) {
		fmt.Printf("%d", n)
		sugar.Debugw("hostWriteI64", "value", n)
	}
}

// HostWriteI32Hex prints an int32 in hexadecimal.
// WASM key: "write_i32x"
func HostWriteI32Hex(sugar *zap.SugaredLogger) func(ctx context.Context, n int32) {
	return func(ctx context.Context, n int32) {
		fmt.Printf("%x", n)
		sugar.Debugw("hostWriteI32Hex", "value", fmt.Sprintf("%x", n))
	}
}

// HostWriteI64Hex prints an int64 in hexadecimal.
// WASM key: "write_i64x"
func HostWriteI64Hex(sugar *zap.SugaredLogger) func(ctx context.Context, n int64) {
	return func(ctx context.Context, n int64) {
		fmt.Printf("%x", n)
		sugar.Debugw("hostWriteI64Hex", "value", fmt.Sprintf("%x", n))
	}
}

// HostWriteDeltaTimestamp prints a nanosecond duration in human-readable form.
// WASM key: "write_delta_timestamp"
func HostWriteDeltaTimestamp(sugar *zap.SugaredLogger) func(ctx context.Context, delta int64) {
	return func(ctx context.Context, delta int64) {

		d := time.Duration(delta)
		fmt.Printf("duration: %s\n", d)
		sugar.Debugw("hostWriteDeltaTimestamp", "delta", d)
	}
}

// =============================================================================
// Result dump
// !!! Should not be exposed to untrusted WASM modules !!!
// WASM key: "dump_result"
// =============================================================================

// HostDumpResult writes the WASM result buffer to a timestamped file.
// WASM key: "dump_result"
func HostDumpResult(sugar *zap.SugaredLogger) func(ctx context.Context, mod api.Module, resultp, resultLen uint32) {
	return func(ctx context.Context, mod api.Module, resultp, resultLen uint32) {
		data, err := ExtractMem[byte](mod, resultp, resultLen)
		if err != nil {
			sugar.Warnw("hostDumpResult: failed to extract result", "err", err)
			panic(fmt.Errorf("dump_result: failed to extract result: %w", err))
		}

		filename := fmt.Sprintf("results/%s.dat", time.Now().String())
		if err = os.WriteFile(filename, data, 0644); err != nil {
			sugar.Errorw("hostDumpResult: failed to write file", "filename", filename, "err", err)
		}
	}
}
