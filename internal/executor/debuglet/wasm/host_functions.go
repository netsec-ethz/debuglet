// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

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
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm/hostconn"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/tetratelabs/wazero/api"
)

// =============================================================================
// Drainable interface
// =============================================================================

type Drainable interface {
	Drain(ctx context.Context)
}

// =============================================================================
// Helpers
// =============================================================================

// addrPortOf reads the address of a peer the host already holds. A peer whose
// address cannot be read is not admitted: the policy has nothing to decide on.
func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	switch value := addr.(type) {
	case *net.TCPAddr:
		return value.AddrPort(), true
	case *net.UDPAddr:
		return value.AddrPort(), true
	case nil:
		return netip.AddrPort{}, false
	}
	parsed, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return parsed, true
}

// guestBuffer checks the guest's buffer the way a direct read would and
// returns a host-owned buffer of the same size to receive into. Datagrams are
// admitted after they are read, so they are read into the host's memory: a
// sender the policy refuses must leave nothing behind in the guest's buffer,
// and no part of a refused payload may survive as the tail of an admitted one.
func guestBuffer(mod api.Module, ptr, length uint32) ([]byte, error) {
	if _, err := ExtractMem[byte](mod, ptr, length); err != nil {
		return nil, err
	}
	return make([]byte, min(length, MAX_SLICE_LENGTH)), nil
}

// attachSocket puts an admitted, already marked connection under this run's
// bandwidth accounting and registers it, returning its guest handle. It
// consumes conn: every failure path releases it.
func attachSocket(ctx context.Context, env *WasmEnv, conn net.Conn, key string, socketType socket.SocketType) (handle int32, err error) {
	ownsRaw := true
	defer func() {
		if ownsRaw {
			env.RecordCleanupError(conn.Close())
		}
	}()
	limit, err := env.Limiter.GetLimit(env.DebugletID, key)
	if err != nil {
		return -1, fmt.Errorf("failed to get limit for %s: %w", key, err)
	}

	opts := hostconn.HostConnOpts{
		ConnAddr:         key,
		MaximumBandwidth: min(limit.Executor, limit.Address),
		SocketType:       socketType,
	}
	ownsRaw = false // NewConnection consumes conn even on failure.
	hc, err := hostconn.NewConnection(ctx, env.PacketCount, env.DebugletID, conn, opts)
	if err != nil {
		env.RecordCleanupError(hostconn.CleanupError(err))
		return -1, fmt.Errorf("failed to create HostConn: %w", err)
	}
	return env.Registry.Add(hc)
}

// writeAddr writes addr into the guest buffer at (bufPtr, bufLen) and returns
// its length, or -1 if addr is empty, the buffer is too small, or the write
// fails.
func writeAddr(mod api.Module, bufPtr, bufLen uint32, addr string) int32 {
	if addr == "" {
		return -1
	}
	b := []byte(addr)
	if bufLen < uint32(len(b)) {
		return -1
	}
	if !mod.Memory().Write(bufPtr, b) {
		return -1
	}
	return int32(len(b))
}

// =============================================================================
// Generic socket API
// =============================================================================

// HostConnect dials an IP/UDP/TCP(+TLS) connection to the given address and
// registers it in the SocketRegistry. The destination is admitted by the
// network policy first: the address the guest wrote is resolved, checked
// against the operator's rules and the job's declared destinations, and the
// connection is then made to the address that was checked rather than to the
// name, so nothing else can be reached in between. A refused destination is
// never contacted. Returns the socket handle as I32.
// WASM key: "connect_tcp", "connect_ip", "connect_udp", "connect_tls"
func HostConnect(env *WasmEnv, socketType socket.SocketType) func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
	var network string
	var transport netpolicy.Transport
	switch socketType {
	case socket.SocketTypeTLS:
		network, transport = "tcp", netpolicy.TLS
	case socket.SocketTypeICMP4:
		network, transport = "ip4:icmp", netpolicy.ICMP
	case socket.SocketTypeTCP:
		network, transport = "tcp", netpolicy.TCP
	case socket.SocketTypeUDP:
		network, transport = "udp", netpolicy.UDP
	default:
		panic(fmt.Errorf("connect: unknown SocketType %d", socketType))
	}

	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}

		destination, err := env.Net.AdmitDestination(ctx, transport, addr)
		if err != nil {
			env.Logger.Warnw("hostConnect: destination refused", "addr", addr, "transport", transport.String(), "err", err)
			panic(fmt.Errorf("connect: %w", err))
		}

		// The dialer consults the same admitted destination again, in the
		// control hook the operating system calls between creating the socket
		// and connecting it, and marks the socket there for this run's packet
		// attribution.
		dialer, err := hostconn.NewDialer(destination, env.Tagger)
		if err != nil {
			env.Logger.Warnw("hostConnect: failed to create dialer", "err", err)
			panic(fmt.Errorf("connect: %w", err))
		}

		// A destination with several addresses is tried in order, the way
		// dialling the name would have: an unreachable first address must not
		// make the destination unreachable. Each attempt passes the control
		// hook again, so every one of them is an admitted address.
		var conn net.Conn
		var dialed string
		var failures error
		for _, candidate := range destination.DialAddresses() {
			if socketType == socket.SocketTypeTLS {
				tlsDialer := &tls.Dialer{
					NetDialer: &net.Dialer{Control: dialer.Control},
					Config:    tlsConfigFor(env.TlsCfg, destination.ServerName),
				}
				conn, err = tlsDialer.DialContext(ctx, "tcp", candidate)
			} else {
				conn, err = dialer.DialContext(ctx, network, candidate)
			}
			if err == nil {
				dialed = candidate
				break
			}
			failures = errors.Join(failures, fmt.Errorf("%s: %w", candidate, err))
			if ctx.Err() != nil {
				break
			}
		}
		if conn == nil {
			if failures == nil {
				failures = errors.New("no admitted address to dial")
			}
			env.Logger.Warnw("hostConnect: failed to dial", "addr", addr, "err", failures)
			panic(fmt.Errorf("connect: %w", failures))
		}

		conn = tagDatagrams(env, conn, socketType)
		handle, err := attachSocket(ctx, env, conn, destination.Key, socketType)
		if err != nil {
			env.Logger.Warnw("hostConnect: failed to admit connection", "addr", dialed, "err", err)
			panic(fmt.Errorf("connect: %w", err))
		}
		return handle
	}
}

// tlsConfigFor keeps certificate verification about the name the guest asked
// for, even though the handshake runs on the address the policy admitted.
func tlsConfigFor(base *tls.Config, serverName string) *tls.Config {
	if base == nil {
		base = &tls.Config{}
	}
	if serverName == "" || base.ServerName != "" {
		return base
	}
	cfg := base.Clone()
	cfg.ServerName = serverName
	return cfg
}

// isStreamSocket reports whether t is a byte-stream transport (TCP or TLS),
// for which io.EOF is the normal end of stream rather than an error.
func isStreamSocket(t socket.SocketType) bool {
	return t == socket.SocketTypeTCP || t == socket.SocketTypeTLS
}

// HostReceiveData performs one underlying read of up to bufLen bytes from the
// socket at sockID into the guest buffer at bufp and returns the number of
// bytes read as I32. For TCP/TLS sockets io.EOF is the normal end of stream:
// bytes returned together with EOF are delivered with their count and a clean
// EOF returns 0, so the guest sees the stream end on the next read. A TCP/TLS
// read that makes no progress into a nonempty buffer, (0,nil), traps with
// io.ErrNoProgress instead of being reported as a false EOF or retried. For
// UDP/ICMP sockets a zero-length datagram returns 0 and EOF remains an error.
// Any other error, on any socket type, traps per the host-function convention.
// WASM key: "receive_tcp_data", "receive_udp_data", "receive_icmp4_data"
func HostReceiveData(env *WasmEnv) func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) int32 {
		sock, err := env.Registry.Get(sockID)
		if err != nil {
			env.Logger.Warnw("hostReceiveData: invalid handle", "handle", sockID, "err", err)
			panic(fmt.Errorf("receive_data: %w", err))
		}

		buf, err := ExtractMem[byte](mod, bufp, bufLen)
		if err != nil {
			panic(err)
		}

		stream := isStreamSocket(sock.Type())
		n, err := sock.Read(buf)
		if err != nil {
			if stream && errors.Is(err, io.EOF) {
				// Normal end of stream: any bytes read alongside EOF are
				// already in guest memory; return their count (0 at a clean
				// EOF) and let the guest interpret it.
				return int32(n)
			}
			env.Logger.Warnw("hostReceiveData: read error", "err", err)
			panic(fmt.Errorf("receive_data: read error: %w", err))
		}
		if stream && n == 0 && len(buf) > 0 {
			env.Logger.Warnw("hostReceiveData: no progress on stream read", "handle", sockID, "len", len(buf))
			panic(fmt.Errorf("receive_data: read error: no progress on stream read into %d-byte buffer: %w", len(buf), io.ErrNoProgress))
		}

		return int32(n)
	}
}

// HostSendData writes size bytes starting at offset ptr from the WASM
// memory to the socket at sockID.
// WASM key: "send_tcp_data", "send_icmp4_data"
func HostSendData(env *WasmEnv) func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) {
	return func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) {
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

func HostDrain(env *WasmEnv) func(ctx context.Context, sockID int32) {
	return func(ctx context.Context, sockID int32) {
		sock, err := env.Registry.Get(sockID)
		if err != nil {
			env.Logger.Warnw("hostDrain: invalid handle", "handle", sockID, "err", err)
			panic(fmt.Errorf("drain_connection: %w", err))
		}
		if d, ok := sock.(Drainable); ok {
			d.Drain(ctx)
		}
	}
}

// HostGetRemoteAddr writes the socket peer's full "host:port" address into the
// guest buffer and returns its length, or -1 if unavailable/too small.
// WASM key: "get_remote_addr"
func HostGetRemoteAddr(env *WasmEnv) func(ctx context.Context, mod api.Module, sockID int32, bufPtr, bufLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, sockID int32, bufPtr, bufLen uint32) int32 {
		sock, err := env.Registry.Get(sockID)
		if err != nil {
			env.Logger.Warnw("hostGetRemoteAddr: invalid handle", "handle", sockID, "err", err)
			panic(fmt.Errorf("get_remote_addr: %w", err))
		}

		return writeAddr(mod, bufPtr, bufLen, sock.RemoteAddr())
	}
}

// =============================================================================
// TCP socket API
// =============================================================================

// HostAcceptTCP accepts one incoming TCP connection on the job's listener and
// registers it in the SocketRegistry. An accepted peer is admitted by the same
// policy as an outbound destination and accounted against the same limits: a
// peer the policy refuses is closed without ever being handed to the guest,
// and the next connection is accepted in its place. Returns the socket handle
// as I32.
// WASM key: "accept_tcp"
func HostAcceptTCP(env *WasmEnv) func(ctx context.Context) int32 {
	return func(ctx context.Context) int32 {
		if err := env.Net.AvailableListener(netpolicy.TCP); err != nil {
			env.Logger.Warnw("hostAcceptTCP: inbound refused", "err", err)
			panic(fmt.Errorf("accept_tcp: %w", err))
		}
		if env.TcpServer == nil {
			panic(fmt.Errorf("accept_tcp: %w", net.ErrClosed))
		}
		for {
			if err := ctx.Err(); err != nil {
				panic(fmt.Errorf("accept_tcp: %w", context.Cause(ctx)))
			}
			conn, err := env.TcpServer.AcceptTCP()
			if err != nil {
				env.Logger.Warnw("hostAcceptTCP: failed to accept", "err", err)
				panic(fmt.Errorf("accept_tcp: %w", err))
			}

			peer, ok := addrPortOf(conn.RemoteAddr())
			if !ok {
				env.Logger.Warnw("hostAcceptTCP: peer has no readable address", "peer", conn.RemoteAddr())
				env.RecordCleanupError(conn.Close())
				continue
			}
			match, err := env.Net.AdmitAddr(ctx, netpolicy.Inbound, peer)
			if err != nil {
				env.Logger.Warnw("hostAcceptTCP: peer refused", "peer", peer.String(), "err", err)
				env.RecordCleanupError(conn.Close())
				continue
			}

			// Linux copies the listener's mark to the connections it accepts;
			// marking again does not rely on that.
			if err := markSocket(env, conn); err != nil {
				env.Logger.Warnw("hostAcceptTCP: failed to mark connection", "peer", peer.String(), "err", err)
				env.RecordCleanupError(conn.Close())
				panic(fmt.Errorf("accept_tcp: %w", err))
			}
			handle, err := attachSocket(ctx, env, conn, match.Key, socket.SocketTypeTCP)
			if err != nil {
				env.Logger.Warnw("hostAcceptTCP: failed to admit connection", "peer", peer.String(), "err", err)
				panic(fmt.Errorf("accept_tcp: %w", err))
			}
			return handle
		}
	}
}

// HostGetTCPAddr writes the public "host:port" of the TCP listener into the
// guest buffer and returns its length, or -1 if unavailable/too small.
// WASM key: "get_tcp_addr"
func HostGetTCPAddr(env *WasmEnv) func(ctx context.Context, mod api.Module, bufPtr, bufLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, bufPtr, bufLen uint32) int32 {
		return writeAddr(mod, bufPtr, bufLen, env.TcpServerAddr)
	}
}

// =============================================================================
// UDP socket API
// WASM keys: "get_udp_addr", "receive_udp_from". Connected-UDP reads/writes
// reuse the generic socket API above ("receive_udp_data", "send_udp_data").
// =============================================================================

// HostGetUDPAddr writes the public "host:port" of the UDP listener into the
// guest buffer and returns its length, or -1 if unavailable/too small.
// WASM key: "get_udp_addr"
func HostGetUDPAddr(env *WasmEnv) func(ctx context.Context, mod api.Module, bufPtr, bufLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, bufPtr, bufLen uint32) int32 {
		return writeAddr(mod, bufPtr, bufLen, env.UdpServerAddr)
	}
}

// HostReceiveUDPFrom reads one admitted datagram from the job's UDP listener
// into the buffer at recvp and writes the sender's "host:port" into senderp.
// The address length is stored as a little-endian uint32 at addrLenp so the
// guest can slice senderp precisely and avoid trailing NULs. Senders the
// policy refuses are dropped and never delivered; an admitted datagram is
// accounted against the same limits as the rest of the run's traffic. Returns
// the number of bytes read as I32; a read error panics per the host-function
// convention. No deadline handling is applied: the executor's debuglet timeout
// closes UdpServer, which unblocks a pending read.
// WASM key: "receive_udp_from"
func HostReceiveUDPFrom(env *WasmEnv) func(ctx context.Context, mod api.Module, recvp, recvLen, senderp, senderLen, addrLenp uint32) int32 {
	return func(ctx context.Context, mod api.Module, recvp, recvLen, senderp, senderLen, addrLenp uint32) int32 {
		if err := env.Net.AvailableListener(netpolicy.UDP); err != nil {
			env.Logger.Warnw("hostReceiveUDPFrom: inbound refused", "err", err)
			panic(fmt.Errorf("receive_udp_from: %w", err))
		}
		buf, err := guestBuffer(mod, recvp, recvLen)
		if err != nil {
			env.Logger.Warnw("hostReceiveUDPFrom: failed to extract buffer", "err", err)
			panic(fmt.Errorf("receive_udp_from: failed to extract buffer: %w", err))
		}
		if env.UdpServer == nil {
			panic(fmt.Errorf("receive_udp_from: %w", net.ErrClosed))
		}

		for {
			if err := ctx.Err(); err != nil {
				panic(fmt.Errorf("receive_udp_from: %w", context.Cause(ctx)))
			}
			n, from, err := env.UdpServer.ReadFrom(buf)
			if err != nil {
				env.Logger.Warnw("hostReceiveUDPFrom: read error", "err", err, "n", n)
				panic(fmt.Errorf("receive_udp_from: read error: %w", err))
			}

			peer, ok := addrPortOf(from)
			if !ok {
				env.Logger.Warnw("hostReceiveUDPFrom: sender has no readable address", "from", from)
				continue
			}
			match, err := env.Net.AdmitAddr(ctx, netpolicy.Inbound, peer)
			if err != nil {
				env.Logger.Warnw("hostReceiveUDPFrom: sender refused", "from", peer.String(), "err", err)
				continue
			}
			if err := env.Accountant.Account(ctx, app.TransferIn, match.Key, n); err != nil {
				env.Logger.Warnw("hostReceiveUDPFrom: failed to account datagram", "from", peer.String(), "err", err)
				panic(fmt.Errorf("receive_udp_from: %w", err))
			}

			if n > 0 && !mod.Memory().Write(recvp, buf[:n]) {
				env.Logger.Warnw("hostReceiveUDPFrom: failed to write the datagram", "n", n)
				panic(fmt.Errorf("receive_udp_from: failed to write %d bytes into the guest buffer", n))
			}

			fromAddr := from.String()
			addrLen := writeAddr(mod, senderp, senderLen, fromAddr)
			if addrLen < 0 {
				env.Logger.Warnw("hostReceiveUDPFrom: failed to write sender address", "from", fromAddr)
				panic(fmt.Errorf("receive_udp_from: sender buffer too small for %q", fromAddr))
			}
			if !mod.Memory().WriteUint32Le(addrLenp, uint32(addrLen)) {
				env.Logger.Warnw("hostReceiveUDPFrom: failed to write sender address length", "from", fromAddr)
				panic(fmt.Errorf("receive_udp_from: failed to write sender address length"))
			}
			return int32(n)
		}
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

// scionDestination admits one SCION destination. A SCION address carries the
// host and port the packet is delivered to, so the operator's destination and
// port rules and the job's declared destinations apply to it as they do to any
// other transport. An address this host would have to resolve over SCION is
// not something the policy can decide on and is refused.
func scionDestination(ctx context.Context, env *WasmEnv, addr string) (netpolicy.Match, error) {
	if err := env.Net.Available(netpolicy.SCION); err != nil {
		return netpolicy.Match{}, err
	}
	udpAddr, err := pan.ParseUDPAddr(addr)
	if err != nil {
		return netpolicy.Match{}, fmt.Errorf("%q is not a SCION address: %w", addr, err)
	}
	return env.Net.AdmitAddr(ctx, netpolicy.SCION, netip.AddrPortFrom(udpAddr.IP, udpAddr.Port))
}

// scionConn admits the destination and only then obtains the connection to it,
// so a refused destination is never dialled.
func scionConn(ctx context.Context, env *WasmEnv, addr string) (*socket.SCIONConn, netpolicy.Match, error) {
	match, err := scionDestination(ctx, env, addr)
	if err != nil {
		return nil, netpolicy.Match{}, err
	}
	sc, err := env.ScionConn.GetOrDial(ctx, addr, env.Logger, env.Tagger)
	if err != nil {
		return nil, netpolicy.Match{}, err
	}
	return sc, match, nil
}

// HostSendSCIONUDPPacket dials (or reuses) a SCION connection to the admitted
// destination and writes size bytes from udp_send_buffer. The packet is
// accounted against the run's limits before it is written, so a SCION send is
// not an unmetered path around the ordinary socket wrappers.
// Returns the send timestamp as I64.
// WASM key: "send_scion_udp_packet"
func HostSendSCIONUDPPacket(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}

		sc, match, err := scionConn(ctx, env, addr)
		if err != nil {
			env.Logger.Warnw("hostSendSCIONUDPPacket: destination refused", "addr", addr, "err", err)
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

		if err := env.Accountant.Account(ctx, app.TransferOut, match.Key, len(data)); err != nil {
			env.Logger.Warnw("hostSendSCIONUDPPacket: failed to account packet", "err", err)
			panic(fmt.Errorf("send_scion_udp_packet: %w", err))
		}
		if _, err = (*sc.Conn).Write(data); err != nil {
			env.Logger.Warnw("hostSendSCIONUDPPacket: write failed", "err", err)
			panic(fmt.Errorf("send_scion_udp_packet: write failed: %w", err))
		}
		return time.Now().UnixNano()
	}
}

// HostReceiveSCIONServerUDPPacket reads one admitted packet from the SCION
// server listener into udp_receive_buffer. timeout is the deadline in
// milliseconds. Packets from a peer the policy refuses are dropped and the
// read continues until the deadline. Returns (bytesRead I32, timestamp I64).
// lastReceived is updated in place.
// WASM key: "receive_scion_server_udp_packet"
func HostReceiveSCIONServerUDPPacket(env *WasmEnv) func(ctx context.Context, mod api.Module, recvp, recvLen uint32, timeout int32) (int32, int64) {
	return func(ctx context.Context, mod api.Module, recvp, recvLen uint32, timeout int32) (int32, int64) {
		if err := env.Net.AvailableListener(netpolicy.SCION); err != nil {
			env.Logger.Warnw("hostReceiveSCIONServerUDPPacket: inbound refused", "err", err)
			panic(fmt.Errorf("receive_scion_server_udp_packet: %w", err))
		}
		buf, err := guestBuffer(mod, recvp, recvLen)
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

		for {
			n, from, err := env.ScionServer.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					env.Logger.Debugw("hostReceiveSCIONServerUDPPacket: read timeout", "timeout", timeout)
					env.LastReceived = nil
					return 0, time.Now().UnixNano()
				}
				env.Logger.Warnw("hostReceiveSCIONServerUDPPacket: read error", "err", err, "n", n)
				panic(fmt.Errorf("receive_scion_server_udp_packet: read error: %w", err))
			}

			match, err := scionPeer(ctx, env, from)
			if err != nil {
				env.Logger.Warnw("hostReceiveSCIONServerUDPPacket: sender refused", "from", from, "err", err)
				continue
			}
			if err := env.Accountant.Account(ctx, app.TransferIn, match.Key, n); err != nil {
				env.Logger.Warnw("hostReceiveSCIONServerUDPPacket: failed to account packet", "err", err)
				panic(fmt.Errorf("receive_scion_server_udp_packet: %w", err))
			}
			if n > 0 && !mod.Memory().Write(recvp, buf[:n]) {
				env.Logger.Warnw("hostReceiveSCIONServerUDPPacket: failed to write the packet", "n", n)
				panic(fmt.Errorf("receive_scion_server_udp_packet: failed to write %d bytes into the guest buffer", n))
			}
			env.LastReceived = from
			return int32(n), time.Now().UnixNano()
		}
	}
}

// scionPeer admits a SCION peer the listener already holds.
func scionPeer(ctx context.Context, env *WasmEnv, from net.Addr) (netpolicy.Match, error) {
	if err := env.Net.Available(netpolicy.SCION); err != nil {
		return netpolicy.Match{}, err
	}
	udpAddr, ok := from.(pan.UDPAddr)
	if !ok {
		return netpolicy.Match{}, fmt.Errorf("peer %v is not a SCION address", from)
	}
	return env.Net.AdmitAddr(ctx, netpolicy.SCION, netip.AddrPortFrom(udpAddr.IP, udpAddr.Port))
}

// HostAnswerSCIONUDPPacket replies to the last received SCION packet, or falls
// back to dialling the given address if no packet has been received yet.
// Either way the peer is admitted again and the reply is accounted, so the
// answer path carries the same policy and limits as an ordinary send.
// WASM key: "answer_scion_udp_packet"
func HostAnswerSCIONUDPPacket(env *WasmEnv, addresses []string) func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
		data, err := ExtractMem[byte](mod, sendp, sendLen)
		if err != nil {
			env.Logger.Warnw("hostAnswerSCIONUDPPacket: failed to extract buffer", "err", err)
			panic(fmt.Errorf("answer_scion_udp_packet: failed to extract buffer: %w", err))
		}

		if env.LastReceived != nil {
			lastReceivedAddr, ok := env.LastReceived.(pan.UDPAddr)
			if !ok {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: could not cast lastReceived to UDPAddr", "addr", env.LastReceived)
				panic(fmt.Errorf("answer_scion_udp_packet: could not cast lastReceived to UDPAddr"))
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

			match, err := scionPeer(ctx, env, lastReceivedAddr)
			if err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: peer refused", "dst", lastReceivedAddr, "err", err)
				panic(fmt.Errorf("answer_scion_udp_packet: %w", err))
			}
			if err := env.Accountant.Account(ctx, app.TransferOut, match.Key, len(data)); err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: failed to account packet", "err", err)
				panic(fmt.Errorf("answer_scion_udp_packet: %w", err))
			}

			env.Logger.Debugw("hostAnswerSCIONUDPPacket: writing", "dst", lastReceivedAddr)
			if _, err = env.ScionServer.WriteTo(data, lastReceivedAddr); err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: write failed", "err", err)
				panic(fmt.Errorf("answer_scion_udp_packet: write failed: %w", err))
			}
		} else {
			env.Logger.Warnln("hostAnswerSCIONUDPPacket: lastReceived is nil, falling back to dial")
			addr, err := ExtractStr(mod, addrp, addrLen)
			if err != nil {
				panic(err)
			}
			sc, match, err := scionConn(ctx, env, addr)
			if err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: destination refused", "addr", addr, "err", err)
				panic(fmt.Errorf("answer_scion_udp_packet: %w", err))
			}
			if err := env.Accountant.Account(ctx, app.TransferOut, match.Key, len(data)); err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: failed to account packet", "err", err)
				panic(fmt.Errorf("answer_scion_udp_packet: %w", err))
			}
			if _, err = (*sc.Conn).Write(data); err != nil {
				env.Logger.Warnw("hostAnswerSCIONUDPPacket: write failed", "err", err)
				panic(fmt.Errorf("answer_scion_udp_packet: write failed: %w", err))
			}
		}
		return time.Now().UnixNano()
	}
}

// HostSCIONAvailablePaths returns the number of available SCION paths to the
// admitted destination.
// WASM key: "scion_available_paths"
func HostSCIONAvailablePaths(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, _, err := scionConn(ctx, env, addr)
		if err != nil {
			env.Logger.Warnw("hostSCIONAvailablePaths: destination refused", "addr", addr, "err", err)
			panic(fmt.Errorf("scion_available_paths: %w", err))
		}

		return int32(len(sc.Selector.Paths()))
	}
}

// HostSCIONPathLength returns the hop count of path at index pathIdx for
// the connection to the admitted destination.
// WASM key: "scion_path_length"
func HostSCIONPathLength(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) int32 {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) int32 {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, _, err := scionConn(ctx, env, addr)
		if err != nil {
			env.Logger.Warnw("hostSCIONPathLength: destination refused", "addr", addr, "err", err)
			panic(fmt.Errorf("scion_path_length: %w", err))
		}

		paths := sc.Selector.Paths()
		hops := len(paths[pathIdx].Metadata.Interfaces) / 2
		return int32(hops)
	}
}

// HostSCIONGetInterfaceDetails returns the IA and IfID of interface ifIdx
// on path pathIdx for the connection to the admitted destination.
// WASM key: "scion_get_interface_details"
func HostSCIONGetInterfaceDetails(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64) {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64) {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, _, err := scionConn(ctx, env, addr)
		if err != nil {
			env.Logger.Warnw("hostSCIONGetInterfaceDetails: destination refused", "addr", addr, "err", err)
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

// HostSCIONSelectPath forces the path selector for the admitted destination to
// use path index pathIdx.
// WASM key: "scion_select_path"
func HostSCIONSelectPath(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) {
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) {
		addr, err := ExtractStr(mod, addrp, addrLen)
		if err != nil {
			panic(err)
		}
		sc, _, err := scionConn(ctx, env, addr)
		if err != nil {
			env.Logger.Warnw("hostSCIONSelectPath: destination refused", "addr", addr, "err", err)
			panic(fmt.Errorf("scion_select_path: %w", err))
		}

		env.Logger.Debugw("hostSCIONSelectPath: forcing path", "index", pathIdx)
		sc.Selector.ForcePath(int(pathIdx))
		env.Logger.Debugw("hostSCIONSelectPath: path selected", "path", sc.Selector.Path())
	}
}
