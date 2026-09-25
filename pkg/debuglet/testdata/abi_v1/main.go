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

// abi_v1 is the frozen guest fixture for guest ABI
// "debuglet-go-wasi-imports-v1". It declares every host import of that ABI
// itself instead of calling the SDK, so its import section is fixed by this
// file and does not follow later SDK changes. The compatibility suite compiles
// it with the pinned toolchain and executes it against the executor's real
// host imports: a renamed import, a changed signature, a changed ownership
// rule or a changed transfer unit makes one of its cases fail.
//
// The executor passes guest arguments verbatim, without a program name.
// os.Args[0] selects the case; os.Args[1], when present, is the target address.
// Every case prints deterministic lines; cases that end in a host trap print
// their last line before the call that traps.
package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"
)

// =============================================================================
// Guest ABI v1 host imports (wazero "env" module).
//
// Every address and buffer is a pair of 32-bit values: an offset into this
// module's linear memory and a length in bytes. The guest owns the memory and
// keeps it alive for the duration of the call; the host only reads or writes
// it while the call runs.
// =============================================================================

//go:wasmimport env connect_tcp
func connectTCP(addrp, addrLen uint32) int32

//go:wasmimport env connect_tls
func connectTLS(addrp, addrLen uint32) int32

//go:wasmimport env connect_udp
func connectUDP(addrp, addrLen uint32) int32

//go:wasmimport env connect_icmp4
func connectICMP4(addrp, addrLen uint32) int32

//go:wasmimport env accept_tcp
func acceptTCP() int32

//go:wasmimport env get_tcp_addr
func getTCPAddr(bufp, bufLen uint32) int32

//go:wasmimport env get_udp_addr
func getUDPAddr(bufp, bufLen uint32) int32

//go:wasmimport env get_remote_addr
func getRemoteAddr(sock, bufp, bufLen uint32) int32

//go:wasmimport env receive_tcp_data
func receiveTCPData(sock, bufp, bufLen uint32) int32

//go:wasmimport env send_tcp_data
func sendTCPData(sock, bufp, bufLen uint32)

//go:wasmimport env receive_udp_data
func receiveUDPData(sock, bufp, bufLen uint32) int32

//go:wasmimport env send_udp_data
func sendUDPData(sock, bufp, bufLen uint32)

//go:wasmimport env receive_udp_from
func receiveUDPFrom(recvp, recvLen, senderp, senderLen, addrLenp uint32) int32

//go:wasmimport env receive_icmp4_data
func receiveICMP4Data(sock, bufp, bufLen uint32) int32

//go:wasmimport env send_icmp4_data
func sendICMP4Data(sock, bufp, bufLen uint32)

//go:wasmimport env drain_connection
func drainConnection(sock uint32)

//go:wasmimport env close_tcp
func closeTCP(sock uint32)

//go:wasmimport env close_icmp4
func closeICMP4(sock uint32)

const (
	// ioBuf is an ordinary receive buffer, well below the host's per-call
	// transfer bound.
	ioBuf = 4096
	// overBuf is deliberately larger than that bound so the io_bound case
	// reports how much of one buffer a single host call moves.
	overBuf = 16384
	// addrBuf holds a "host:port" address; the host rejects a buffer that is
	// too small rather than truncating the address.
	addrBuf = 512
	// senderBuf holds the sender address of one received datagram.
	senderBuf = 64
)

func strPtr(s string) uint32 { return uint32(uintptr(unsafe.Pointer(unsafe.StringData(s)))) }

func bytePtr(b []byte) uint32 { return uint32(uintptr(unsafe.Pointer(&b[0]))) }

func main() {
	// Never true: it only stops the linker from dropping unused imports.
	keepImports(len(os.Args) > 4096)

	if len(os.Args) == 0 {
		fmt.Println("usage: the case name is the first guest argument")
		os.Exit(2)
	}
	target := ""
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	switch os.Args[0] {
	case "tcp_exchange":
		tcpExchange(target)
	case "tcp_connect_only":
		tcpConnectOnly(target)
	case "tls_connect_only":
		tlsConnectOnly(target)
	case "tcp_block":
		tcpBlock(target)
	case "udp_echo":
		udpEcho(target)
	case "listen_tcp":
		listenTCP()
	case "listen_udp":
		listenUDP()
	case "no_listener":
		noListener()
	case "io_bound":
		ioBound(target)
	case "clock":
		clock()
	default:
		fmt.Printf("unknown case %q\n", os.Args[0])
		os.Exit(2)
	}
}

// connected reports the outcome of a connect import. A negative handle is the
// only failure the ABI reports as a value; every other connect failure aborts
// the guest inside the host call.
func connected(label string, handle int32) uint32 {
	if handle < 0 {
		fmt.Printf("connect %s rc=%d\n", label, handle)
		os.Exit(1)
	}
	fmt.Printf("connected %s handle=%d\n", label, handle)
	return uint32(handle)
}

// receive prints one stream read. A zero count on a TCP or TLS socket is the
// peer's clean end of stream.
func receive(label string, n int32, buf []byte) bool {
	if n < 0 {
		fmt.Printf("%s rc=%d\n", label, n)
		os.Exit(1)
	}
	if n == 0 {
		fmt.Printf("%s eof\n", label)
		return false
	}
	fmt.Printf("%s n=%d data=%q\n", label, n, buf[:n])
	return true
}

func remoteAddr(sock uint32) {
	buf := make([]byte, addrBuf)
	n := getRemoteAddr(sock, bytePtr(buf), uint32(len(buf)))
	if n < 0 {
		fmt.Println("remote rc=-1")
		return
	}
	fmt.Printf("remote=%s\n", buf[:n])
}

// tcpExchange writes one request, reads the reply until the peer closes, and
// releases the socket.
func tcpExchange(addr string) {
	fmt.Printf("connecting tcp %s\n", addr)
	sock := connected("tcp", connectTCP(strPtr(addr), uint32(len(addr))))
	remoteAddr(sock)

	request := []byte("PING\n")
	sendTCPData(sock, bytePtr(request), uint32(len(request)))
	fmt.Printf("sent=%d\n", len(request))

	buf := make([]byte, ioBuf)
	total := 0
	for {
		n := receiveTCPData(sock, bytePtr(buf), uint32(len(buf)))
		if !receive("recv", n, buf) {
			break
		}
		total += int(n)
	}
	fmt.Printf("total=%d\n", total)

	drainConnection(sock)
	fmt.Println("drained")
	closeTCP(sock)
	fmt.Println("closed")
}

// tcpConnectOnly is used for the refused and policy-denied cases: both abort
// the guest inside connect_tcp, so "connected tcp" is never printed.
func tcpConnectOnly(addr string) {
	fmt.Printf("connecting tcp %s\n", addr)
	sock := connected("tcp", connectTCP(strPtr(addr), uint32(len(addr))))
	closeTCP(sock)
	fmt.Println("closed")
}

// tlsConnectOnly dials TLS. Against a plaintext peer the handshake fails
// inside the host call and the guest is aborted.
func tlsConnectOnly(addr string) {
	fmt.Printf("connecting tls %s\n", addr)
	sock := connected("tls", connectTLS(strPtr(addr), uint32(len(addr))))
	closeTCP(sock)
	fmt.Println("closed")
}

// tcpBlock blocks in receive_tcp_data. Host imports carry no deadline of their
// own: only the job's execution budget ends this guest.
func tcpBlock(addr string) {
	fmt.Printf("connecting tcp %s\n", addr)
	sock := connected("tcp", connectTCP(strPtr(addr), uint32(len(addr))))
	buf := make([]byte, ioBuf)
	fmt.Println("blocking")
	n := receiveTCPData(sock, bytePtr(buf), uint32(len(buf)))
	fmt.Printf("returned n=%d\n", n)
}

// udpEcho uses a connected UDP socket: one datagram out, one datagram back.
// A zero count is an empty datagram here, never an end of stream.
func udpEcho(addr string) {
	fmt.Printf("connecting udp %s\n", addr)
	sock := connected("udp", connectUDP(strPtr(addr), uint32(len(addr))))
	remoteAddr(sock)

	request := []byte("PING")
	sendUDPData(sock, bytePtr(request), uint32(len(request)))
	fmt.Printf("sent=%d\n", len(request))

	buf := make([]byte, ioBuf)
	n := receiveUDPData(sock, bytePtr(buf), uint32(len(buf)))
	if n < 0 {
		fmt.Printf("recv rc=%d\n", n)
		os.Exit(1)
	}
	fmt.Printf("recv n=%d data=%q\n", n, buf[:n])
	closeTCP(sock)
	fmt.Println("closed")
}

// listenTCP publishes the job's TCP listener, serves exactly one connection
// and waits for its peer's end of stream.
func listenTCP() {
	buf := make([]byte, addrBuf)
	n := getTCPAddr(bytePtr(buf), uint32(len(buf)))
	if n < 0 {
		fmt.Println("listen tcp rc=-1")
		os.Exit(1)
	}
	fmt.Printf("listening tcp %s\n", buf[:n])

	sock := connected("accept", acceptTCP())
	remoteAddr(sock)

	data := make([]byte, ioBuf)
	receive("recv", receiveTCPData(sock, bytePtr(data), uint32(len(data))), data)

	reply := []byte("PONG\n")
	sendTCPData(sock, bytePtr(reply), uint32(len(reply)))
	fmt.Printf("sent=%d\n", len(reply))

	receive("recv2", receiveTCPData(sock, bytePtr(data), uint32(len(data))), data)
	closeTCP(sock)
	fmt.Println("closed")
}

// listenUDP publishes the job's UDP listener and reports one datagram together
// with its sender address.
func listenUDP() {
	buf := make([]byte, addrBuf)
	n := getUDPAddr(bytePtr(buf), uint32(len(buf)))
	if n < 0 {
		fmt.Println("listen udp rc=-1")
		os.Exit(1)
	}
	fmt.Printf("listening udp %s\n", buf[:n])

	data := make([]byte, ioBuf)
	sender := make([]byte, senderBuf)
	var addrLen int32
	got := receiveUDPFrom(bytePtr(data), uint32(len(data)), bytePtr(sender), uint32(len(sender)),
		uint32(uintptr(unsafe.Pointer(&addrLen))))
	if got < 0 {
		fmt.Printf("recvfrom rc=%d\n", got)
		os.Exit(1)
	}
	if addrLen < 0 || int(addrLen) > len(sender) {
		fmt.Printf("recvfrom addrlen=%d\n", addrLen)
		os.Exit(1)
	}
	fmt.Printf("recvfrom n=%d data=%q sender=%s\n", got, data[:got], sender[:addrLen])
}

// noListener records what the listener addresses report for a job that
// requested neither listener.
func noListener() {
	buf := make([]byte, addrBuf)
	fmt.Printf("tcp_addr rc=%d\n", getTCPAddr(bytePtr(buf), uint32(len(buf))))
	fmt.Printf("udp_addr rc=%d\n", getUDPAddr(bytePtr(buf), uint32(len(buf))))
}

// ioBound offers one buffer larger than the host's per-call transfer bound.
// The peer counts what actually arrived.
func ioBound(addr string) {
	fmt.Printf("connecting tcp %s\n", addr)
	sock := connected("tcp", connectTCP(strPtr(addr), uint32(len(addr))))

	payload := make([]byte, overBuf)
	for i := range payload {
		payload[i] = 'A'
	}
	sendTCPData(sock, bytePtr(payload), uint32(len(payload)))
	fmt.Printf("offered=%d\n", len(payload))

	closeTCP(sock)
	fmt.Println("closed")
}

// clock proves that the executor supplies WASI monotonic time and sleep: the
// ABI itself carries no clock import, and every duration a guest reports comes
// from its own standard library.
func clock() {
	start := time.Now()
	time.Sleep(50 * time.Millisecond)
	fmt.Printf("slept=%t\n", time.Since(start) >= 40*time.Millisecond)
}

// keepImports references every ABI v1 import so that the compiled module's
// import section is complete whichever case runs. run is never true.
func keepImports(run bool) {
	if !run {
		return
	}
	addr := "127.0.0.1:1"
	buf := make([]byte, 8)
	sender := make([]byte, 8)
	var addrLen int32
	p, plen := strPtr(addr), uint32(len(addr))
	b, blen := bytePtr(buf), uint32(len(buf))

	report(connectTCP(p, plen))
	report(connectTLS(p, plen))
	report(connectUDP(p, plen))
	report(connectICMP4(p, plen))
	report(acceptTCP())
	report(getTCPAddr(b, blen))
	report(getUDPAddr(b, blen))
	report(getRemoteAddr(0, b, blen))
	report(receiveTCPData(0, b, blen))
	report(receiveUDPData(0, b, blen))
	report(receiveICMP4Data(0, b, blen))
	report(receiveUDPFrom(b, blen, bytePtr(sender), uint32(len(sender)),
		uint32(uintptr(unsafe.Pointer(&addrLen)))))
	sendTCPData(0, b, blen)
	sendUDPData(0, b, blen)
	sendICMP4Data(0, b, blen)
	drainConnection(0)
	closeTCP(0)
	closeICMP4(0)
}

func report(v int32) { fmt.Println(v) }
