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

// Package engine contains the WASM host function implementations that are
// imported by WASM modules at runtime. Each host function follows the wasmer
// calling convention: (environment interface{}, args []wasmer.Value) →
// ([]wasmer.Value, error).
//
// Go function names use camelCase with a "host" prefix. The WASM-visible
// import key strings (used in importObject.Register) are left unchanged so
// that existing WASM modules do not need recompilation.
package engine

import (
	"crypto/tls"
	"debuglet/internal/executor/resource"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/wasmerio/wasmer-go/wasmer"
	"go.uber.org/zap"
)

// =============================================================================
// Context / timing
// =============================================================================

// hostWaitStart verifies the execution context is still active.
// WASM key: "wait_start"
func hostWaitStart(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}
	return []wasmer.Value{}, nil
}

// hostGetTimestamp returns the current wall-clock time as a Unix nanosecond timestamp.
// WASM key: "get_timestamp"
func hostGetTimestamp(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}
	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

// hostWaitUntil blocks until the given Unix nanosecond timestamp, or until the
// context is cancelled.
// WASM key: "wait_until"
func hostWaitUntil(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	target := time.Unix(0, args[0].I64())
	select {
	case <-time.After(time.Until(target)):
	case <-env.ctx.Done():
		return nil, checkContextExpired(env)
	}
	return []wasmer.Value{}, nil
}

// hostConnect dials a IP/UDP/TCP(+TLS) connection to addresses[args[0]] and registers
// it in the SocketRegistry. Returns the socket handle as I32.
// WASM key: "connect_tcp", "connect_ip", "connect_udp", "connect_tls"
func hostConnect(
	socketType SocketType,
	environment interface{},
	args []wasmer.Value,
	addresses []string,
	sugar *zap.SugaredLogger,
	registry *SocketRegistry,
	tlsCfg *tls.Config,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	var network string
	switch socketType {
	case SocketTypeTLS:
		network = "tcp"
	case SocketTypeIP:
		network = "ip"
	case SocketTypeTCP:
		network = "tcp"
	case SocketTypeUDP:
		network = "udp"
	default:
		return nil, fmt.Errorf("connect: unknown SocketType %d", socketType)
	}

	addr := addresses[args[0].I32()]

	var conn net.Conn
	var err error

	if socketType == SocketTypeTLS {
		conn, err = tls.Dial("tcp", addr, tlsCfg)
	} else {
		conn, err = net.Dial(network, addr)
	}
	if err != nil {
		sugar.Warnw("hostConnect: failed to dial", "addr", addr, "err", err)
		return nil, fmt.Errorf("connect: failed to dial %q: %w", addr, err)
	}

	socket := NewGenericSocket(conn, socketType)
	handle := registry.Add(socket)
	env.handleToAddr[handle] = addr
	return []wasmer.Value{wasmer.NewI32(handle)}, nil
}

// hostAcceptTCP accepts one incoming TCP connection on the server and registers
// it in the SocketRegistry. Returns the socket handle as I32.
// WASM key: "accept_tcp"
func hostAcceptTCP(
	environment interface{},
	args []wasmer.Value,
	tcpServer *net.TCPListener,
	sugar *zap.SugaredLogger,
	registry *SocketRegistry,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	conn, err := tcpServer.AcceptTCP()
	if err != nil {
		sugar.Warnw("hostAcceptTCP: failed to accept", "err", err)
		return nil, fmt.Errorf("accept_tcp: %w", err)
	}

	handle := registry.Add(NewTCPSocket(conn))
	return []wasmer.Value{wasmer.NewI32(handle)}, nil
}

// hostReceiveData reads up to args[1] bytes from the socket at args[0] into
// the buffer at pointer args[2]. Returns the number of bytes read as I32.
// WASM key: "receive_tcp_data", "receive_ip_data"
func hostReceiveData(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	registry *SocketRegistry,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	sockID := args[0].I32()
	sock, err := registry.Get(sockID)
	if err != nil {
		sugar.Warnw("hostReceiveData: invalid handle", "handle", args[0].I32(), "err", err)
		return nil, fmt.Errorf("receive_data: %w", err)
	}

	size := args[1].I32()
	ptr := args[2].I32()

	memory, err := instance.Exports.GetMemory("memory")
	if err != nil {
		sugar.Errorw("hostReceiveData: failed to extract memory", "err", err)
		return nil, fmt.Errorf("receive_data: failed to extract memory: %w", err)
	}

	if err := ratelimit(env, resource.TransferIn, sockID, size, sugar); err != nil {
		return nil, err
	}

	data := memory.Data()
	buf := data[ptr : ptr+size]

	n, err := sock.Read(buf)
	if err != nil {
		sugar.Warnw("hostReceiveData: read error", "err", err)
		return nil, fmt.Errorf("receive_data: read error: %w", err)
	}
	return []wasmer.Value{wasmer.NewI32(int32(n))}, nil
}

// hostSendData writes args[1] bytes starting at offset args[2] from the WASM
// tcp_send_buffer to the socket at args[0].
// WASM key: "send_tcp_data", "send_ip_data"
func hostSendData(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	registry *SocketRegistry,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	sockID := args[0].I32()
	sock, err := registry.Get(sockID)
	if err != nil {
		sugar.Warnw("hostSendData: invalid handle", "handle", args[0].I32(), "err", err)
		return nil, fmt.Errorf("send_data: %w", err)
	}

	size := args[1].I32()
	ptr := args[2].I32()

	memory, err := instance.Exports.GetMemory("memory")
	if err != nil {
		sugar.Errorw("hostSendData: failed to extract memory", "err", err)
		return nil, fmt.Errorf("send_data: failed to extract memory: %w", err)
	}
	data := memory.Data()
	message := data[ptr : ptr+size]

	if err := ratelimit(env, resource.TransferOut, sockID, size, sugar); err != nil {
		return nil, err
	}

	sugar.Debugw("hostSendData: sending tcp message", "message", string(message))

	if _, err = sock.Write(message); err != nil {
		sugar.Warnw("hostSendData: write error", "err", err)
		return nil, fmt.Errorf("send_data: write error: %w", err)
	}
	return []wasmer.Value{}, nil
}

// hostClose closes the socket at handle args[0].
// WASM key: "close_tcp", "close_ip"
func hostClose(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	registry *SocketRegistry,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	if err := registry.Close(args[0].I32()); err != nil {
		sugar.Warnw("hostClose: close error", "handle", args[0].I32(), "err", err)
		return nil, fmt.Errorf("close_tcp: %w", err)
	}
	return []wasmer.Value{}, nil
}

// =============================================================================
// IP socket API
// WASM keys: "connect_ip", "accept_ip", "receive_ip_data",
//            "send_ip_data", "close_ip"
// =============================================================================

// hostAcceptIP accepts one incoming IP connection on the server and registers
// it in the SocketRegistry. Returns the socket handle as I32.
// WASM key: "accept_ip"
func hostAcceptIP(
	environment interface{},
	args []wasmer.Value,
	ipServer net.Listener,
	sugar *zap.SugaredLogger,
	registry *SocketRegistry,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	conn, err := ipServer.Accept()
	if err != nil {
		sugar.Warnw("hostAcceptIP: failed to accept", "err", err)
		return nil, fmt.Errorf("accept_ip: %w", err)
	}

	ipConn, ok := conn.(*net.IPConn)
	if !ok {
		return nil, fmt.Errorf("accept_ip: expected *net.IPConn, got %T", conn)
	}

	handle := registry.Add(NewIPSocket(ipConn))
	return []wasmer.Value{wasmer.NewI32(handle)}, nil
}

// =============================================================================
// UDP (plain IP) socket API  — !!! NOT YET REGISTERED — infrastructure only !!!
// WASM keys: "send_udp_packet", "receive_udp_packet", "answer_udp_packet"
// =============================================================================

func hostSendUDPPacket(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	udpAddresses []*net.UDPAddr,
	instance *wasmer.Instance,
	udpServer *net.PacketConn,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	dst := udpAddresses[args[0].I32()]
	sugar.Debugw("hostSendUDPPacket sending", "dst", dst)

	contents, err := extractSlice(instance, "udp_send_buffer", 0, args[1].I32())
	if err != nil {
		sugar.Warnw("hostSendUDPPacket: failed to extract buffer", "err", err)
		return nil, fmt.Errorf("send_udp_packet: failed to extract udp_send_buffer: %w", err)
	}

	if _, err = (*udpServer).WriteTo(contents, dst); err != nil {
		sugar.Warnw("hostSendUDPPacket: write error", "err", err)
		return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("send_udp_packet: write error: %w", err)
	}
	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

func hostReceiveUDPPacket(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	lastReceived *net.Addr,
	instance *wasmer.Instance,
	udpServer *net.PacketConn,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	buf, err := extractSlice(instance, "udp_receive_buffer", 0, 1024)
	if err != nil {
		sugar.Warnw("hostReceiveUDPPacket: failed to extract buffer", "err", err)
		return nil, fmt.Errorf("receive_udp_packet: failed to extract udp_receive_buffer: %w", err)
	}

	deadline := time.Now().Add(time.Duration(args[0].I64()) * time.Nanosecond)
	if err := (*udpServer).SetReadDeadline(deadline); err != nil {
		sugar.Warnw("hostReceiveUDPPacket: failed to set deadline", "err", err)
		return nil, fmt.Errorf("receive_udp_packet: failed to set read deadline: %w", err)
	}

	n, addr, err := (*udpServer).ReadFrom(buf)
	if err != nil {
		sugar.Warnw("hostReceiveUDPPacket: read error", "err", err)
		n = -1
	} else {
		*lastReceived = addr
	}
	return []wasmer.Value{wasmer.NewI32(int32(n)), wasmer.NewI64(time.Now().UnixNano())}, nil
}

func hostAnswerUDPPacket(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	lastReceived *net.Addr,
	udpAddresses []*net.UDPAddr,
	instance *wasmer.Instance,
	udpServer *net.PacketConn,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	contents, err := extractSlice(instance, "udp_send_buffer", 0, args[1].I32())
	if err != nil {
		sugar.Warnw("hostAnswerUDPPacket: failed to extract buffer", "err", err)
		return nil, fmt.Errorf("answer_udp_packet: failed to extract udp_send_buffer: %w", err)
	}

	dst := net.Addr(udpAddresses[args[0].I32()])
	if lastReceived != nil {
		dst = *lastReceived
	} else {
		sugar.Warnln("hostAnswerUDPPacket: lastReceived is nil, falling back to address list")
	}

	if _, err = (*udpServer).WriteTo(contents, dst); err != nil {
		sugar.Warnw("hostAnswerUDPPacket: write error", "err", err)
		return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_udp_packet: write error: %w", err)
	}
	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

// =============================================================================
// SCION-UDP API
// WASM keys: "send_scion_udp_packet", "receive_scion_server_udp_packet",
//            "scion_available_paths", "scion_path_length",
//            "scion_get_interface_details", "scion_select_path"
// =============================================================================

// hostSendSCIONUDPPacket dials (or reuses) a SCION connection to
// addresses[args[0]] and writes args[1] bytes from udp_send_buffer.
// Returns the send timestamp as I64.
// WASM key: "send_scion_udp_packet"
func hostSendSCIONUDPPacket(
	environment interface{},
	args []wasmer.Value,
	scionConns *SCIONConnRegistry,
	addresses []string,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	addrIdx := args[0].I32()
	size := args[1].I32()

	sc, err := scionConns.GetOrDial(env.ctx, addresses, addrIdx, sugar)
	if err != nil {
		if ctxErr := checkContextExpired(env); ctxErr != nil {
			return nil, ctxErr
		}
		sugar.Warnw("hostSendSCIONUDPPacket: dial failed", "err", err)
		return nil, fmt.Errorf("send_scion_udp_packet: %w", err)
	}

	data, err := extractSlice(instance, "udp_send_buffer", 0, size)
	if err != nil {
		sugar.Warnw("hostSendSCIONUDPPacket: failed to extract buffer", "err", err)
		return nil, fmt.Errorf("send_scion_udp_packet: failed to extract udp_send_buffer: %w", err)
	}

	deadline, ok := env.ctx.Deadline()
	if !ok {
		return nil, fmt.Errorf("send_scion_udp_packet: debuglet has no deadline")
	}
	(*sc.conn).SetDeadline(deadline)

	if _, err = (*sc.conn).Write(data); err != nil {
		if ctxErr := checkContextExpired(env); ctxErr != nil {
			return nil, ctxErr
		}
		sugar.Warnw("hostSendSCIONUDPPacket: write failed", "err", err)
		return nil, fmt.Errorf("send_scion_udp_packet: write failed: %w", err)
	}
	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

// hostReceiveSCIONServerUDPPacket reads one packet from the SCION server
// listener into udp_receive_buffer. args[0] is the timeout in milliseconds.
// Returns (bytesRead I32, timestamp I64). lastReceived is updated in place.
// WASM key: "receive_scion_server_udp_packet"
func hostReceiveSCIONServerUDPPacket(
	environment interface{},
	args []wasmer.Value,
	lastReceived *net.Addr,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
	scionServer *pan.ListenConn,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	buf, err := extractSlice(instance, "udp_receive_buffer", 0, 1024)
	if err != nil {
		sugar.Warnw("hostReceiveSCIONServerUDPPacket: failed to extract buffer", "err", err)
		return nil, fmt.Errorf("receive_scion_server_udp_packet: failed to extract udp_receive_buffer: %w", err)
	}

	deadline := time.Now().Add(time.Duration(args[0].I32()) * time.Millisecond)
	if ctxDeadline, ok := env.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	if err = (*scionServer).SetReadDeadline(deadline); err != nil {
		sugar.Warnw("hostReceiveSCIONServerUDPPacket: failed to set deadline", "err", err)
		return nil, fmt.Errorf("receive_scion_server_udp_packet: failed to set read deadline: %w", err)
	}

	n, from, err := (*scionServer).ReadFrom(buf)
	if err != nil {
		if ctxErr := checkContextExpired(env); ctxErr != nil {
			return nil, ctxErr
		}
		sugar.Warnw("hostReceiveSCIONServerUDPPacket: read error", "err", err, "n", n)
		*lastReceived = nil
		n = 0
	} else {
		*lastReceived = from
	}
	return []wasmer.Value{wasmer.NewI32(int32(n)), wasmer.NewI64(time.Now().UnixNano())}, nil
}

// hostAnswerSCIONUDPPacket replies to the last received SCION packet, or falls
// back to dialling addresses[args[0]] if no packet has been received yet.
// WASM key: "answer_scion_udp_packet"
func hostAnswerSCIONUDPPacket(
	environment interface{},
	args []wasmer.Value,
	lastReceived *net.Addr,
	scionConns *SCIONConnRegistry,
	addresses []string,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
	scionServer *pan.ListenConn,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	size := args[1].I32()
	data, err := extractSlice(instance, "udp_send_buffer", 0, size)
	if err != nil {
		sugar.Warnw("hostAnswerSCIONUDPPacket: failed to extract buffer", "err", err)
		return nil, fmt.Errorf("answer_scion_udp_packet: failed to extract udp_send_buffer: %w", err)
	}

	if lastReceived != nil && *lastReceived != nil {
		lastReceivedAddr, ok := (*lastReceived).(pan.UDPAddr)
		if !ok {
			sugar.Warnw("hostAnswerSCIONUDPPacket: could not cast lastReceived to UDPAddr", "addr", *lastReceived)
			return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_scion_udp_packet: type assertion failed")
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
			return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_scion_udp_packet: write failed: %w", err)
		}
	} else {
		sugar.Warnln("hostAnswerSCIONUDPPacket: lastReceived is nil, falling back to dial")
		addrIdx := args[0].I32()
		sc, err := scionConns.GetOrDial(env.ctx, addresses, addrIdx, sugar)
		if err != nil {
			sugar.Warnw("hostAnswerSCIONUDPPacket: dial failed", "err", err)
			return nil, fmt.Errorf("answer_scion_udp_packet: %w", err)
		}
		if _, err = (*sc.conn).Write(data); err != nil {
			sugar.Warnw("hostAnswerSCIONUDPPacket: write failed", "err", err)
			return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_scion_udp_packet: write failed: %w", err)
		}
	}
	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

// hostSCIONAvailablePaths returns the number of available SCION paths to
// addresses[args[0]].
// WASM key: "scion_available_paths"
func hostSCIONAvailablePaths(
	environment interface{},
	args []wasmer.Value,
	scionConns *SCIONConnRegistry,
	addresses []string,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	sc, err := scionConns.GetOrDial(env.ctx, addresses, args[0].I32(), sugar)
	if err != nil {
		if ctxErr := checkContextExpired(env); ctxErr != nil {
			return nil, ctxErr
		}
		sugar.Warnw("hostSCIONAvailablePaths: dial failed", "err", err)
		return nil, fmt.Errorf("scion_available_paths: %w", err)
	}

	return []wasmer.Value{wasmer.NewI32(int32(len(sc.selector.Paths())))}, nil
}

// hostSCIONPathLength returns the hop count of path at index args[1] for
// the connection to addresses[args[0]].
// WASM key: "scion_path_length"
func hostSCIONPathLength(
	environment interface{},
	args []wasmer.Value,
	scionConns *SCIONConnRegistry,
	addresses []string,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	sc, err := scionConns.GetOrDial(env.ctx, addresses, args[0].I32(), sugar)
	if err != nil {
		if ctxErr := checkContextExpired(env); ctxErr != nil {
			return nil, ctxErr
		}
		sugar.Warnw("hostSCIONPathLength: dial failed", "err", err)
		return nil, fmt.Errorf("scion_path_length: %w", err)
	}

	pathIdx := args[1].I32()
	paths := sc.selector.Paths()
	hops := len(paths[pathIdx].Metadata.Interfaces) / 2
	return []wasmer.Value{wasmer.NewI32(int32(hops))}, nil
}

// hostSCIONGetInterfaceDetails returns the IA and IfID of interface args[2]
// on path args[1] for the connection to addresses[args[0]].
// WASM key: "scion_get_interface_details"
func hostSCIONGetInterfaceDetails(
	environment interface{},
	args []wasmer.Value,
	scionConns *SCIONConnRegistry,
	addresses []string,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	sc, err := scionConns.GetOrDial(env.ctx, addresses, args[0].I32(), sugar)
	if err != nil {
		if ctxErr := checkContextExpired(env); ctxErr != nil {
			return nil, ctxErr
		}
		sugar.Warnw("hostSCIONGetInterfaceDetails: dial failed", "err", err)
		return nil, fmt.Errorf("scion_get_interface_details: %w", err)
	}

	pathIdx := int(args[1].I32())
	ifIdx := int(args[2].I32())
	paths := sc.selector.Paths()

	sugar.Debugw("hostSCIONGetInterfaceDetails", "path", pathIdx, "interface", ifIdx)

	if pathIdx >= len(paths) || ifIdx >= len(paths[pathIdx].Metadata.Interfaces) {
		return []wasmer.Value{wasmer.NewI64(0), wasmer.NewI64(0)}, nil
	}

	iface := paths[pathIdx].Metadata.Interfaces[ifIdx]
	return []wasmer.Value{
		wasmer.NewI64(int64(iface.IA)),
		wasmer.NewI64(int64(iface.IfID)),
	}, nil
}

// hostSCIONSelectPath forces the path selector for addresses[args[0]] to use
// path index args[1].
// WASM key: "scion_select_path"
func hostSCIONSelectPath(
	environment interface{},
	args []wasmer.Value,
	scionConns *SCIONConnRegistry,
	addresses []string,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	sc, err := scionConns.GetOrDial(env.ctx, addresses, args[0].I32(), sugar)
	if err != nil {
		if ctxErr := checkContextExpired(env); ctxErr != nil {
			return nil, ctxErr
		}
		sugar.Warnw("hostSCIONSelectPath: dial failed", "err", err)
		return nil, fmt.Errorf("scion_select_path: %w", err)
	}

	pathIdx := int(args[1].I32())
	sugar.Debugw("hostSCIONSelectPath: forcing path", "index", pathIdx)
	sc.selector.ForcePath(pathIdx)
	sugar.Debugw("hostSCIONSelectPath: path selected", "path", sc.selector.Path())
	return []wasmer.Value{}, nil
}

// =============================================================================
// Debug write API
// !!! These should not be exposed to untrusted WASM modules !!!
// WASM keys: "write", "write_noeol", "write_i32", "write_i64",
//            "write_i32x", "write_i64x", "write_delta_timestamp"
// =============================================================================

// hostReadWriteBuffer is a shared helper that reads the write_buffer global
// from WASM memory. It is not exported to WASM.
func hostReadWriteBuffer(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]byte, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}
	size := args[0].I32()
	data, err := extractSlice(instance, "write_buffer", 0, size)
	if err != nil {
		sugar.Warnw("hostReadWriteBuffer: failed to extract buffer", "err", err)
		return nil, fmt.Errorf("write: failed to extract write_buffer: %w", err)
	}
	return data, nil
}

// hostWriteString prints a UTF-8 string followed by a newline.
// WASM key: "write"
func hostWriteString(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	data, err := hostReadWriteBuffer(environment, args, sugar, instance)
	if err != nil {
		return nil, err
	}
	fmt.Printf("%s\n", data)
	sugar.Debugw("hostWriteString", "data", data)
	return []wasmer.Value{}, nil
}

// hostWriteStringNoEOL prints a UTF-8 string without a trailing newline.
// WASM key: "write_noeol"
func hostWriteStringNoEOL(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	data, err := hostReadWriteBuffer(environment, args, sugar, instance)
	if err != nil {
		return nil, err
	}
	fmt.Printf("%s", data)
	sugar.Debugw("hostWriteStringNoEOL", "data", data)
	return []wasmer.Value{}, nil
}

// hostWriteI32 prints an int32 in decimal.
// WASM key: "write_i32"
func hostWriteI32(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}
	n := args[0].I32()
	fmt.Printf("%d", n)
	sugar.Debugw("hostWriteI32", "value", n)
	return []wasmer.Value{}, nil
}

// hostWriteI64 prints an int64 in decimal.
// WASM key: "write_i64"
func hostWriteI64(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}
	n := args[0].I64()
	fmt.Printf("%d", n)
	sugar.Debugw("hostWriteI64", "value", n)
	return []wasmer.Value{}, nil
}

// hostWriteI32Hex prints an int32 in hexadecimal.
// WASM key: "write_i32x"
func hostWriteI32Hex(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}
	n := args[0].I32()
	fmt.Printf("%x", n)
	sugar.Debugw("hostWriteI32Hex", "value", fmt.Sprintf("%x", n))
	return []wasmer.Value{}, nil
}

// hostWriteI64Hex prints an int64 in hexadecimal.
// WASM key: "write_i64x"
func hostWriteI64Hex(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}
	n := args[0].I64()
	fmt.Printf("%x", n)
	sugar.Debugw("hostWriteI64Hex", "value", fmt.Sprintf("%x", n))
	return []wasmer.Value{}, nil
}

// hostWriteDeltaTimestamp prints a nanosecond duration in human-readable form.
// WASM key: "write_delta_timestamp"
func hostWriteDeltaTimestamp(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}
	delta := time.Duration(args[0].I64())
	fmt.Printf("duration: %s\n", delta)
	sugar.Debugw("hostWriteDeltaTimestamp", "delta", delta)
	return []wasmer.Value{}, nil
}

// =============================================================================
// Result dump
// !!! Should not be exposed to untrusted WASM modules !!!
// WASM key: "dump_result"
// =============================================================================

// hostDumpResult writes the WASM result buffer to a timestamped file.
// WASM key: "dump_result"
func hostDumpResult(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instance *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(*HostEnvironment)
	if err := checkContextExpired(env); err != nil {
		return nil, err
	}

	size := args[0].I32()
	data, err := extractSlice(instance, "result", 0, size)
	if err != nil {
		sugar.Warnw("hostDumpResult: failed to extract result", "err", err)
		return nil, fmt.Errorf("dump_result: failed to extract result: %w", err)
	}

	filename := fmt.Sprintf("results/%s.dat", time.Now().String())
	if err = os.WriteFile(filename, data, 0644); err != nil {
		sugar.Errorw("hostDumpResult: failed to write file", "filename", filename, "err", err)
	}
	return []wasmer.Value{}, nil
}
