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

// Package debuglet is the Go client library for writing debuglets (WASM
// measurement programs) that run on the Debuglet executor.
//
// A debuglet is a standard WASI command module: write a normal `func main()`,
// build it with `GOOS=wasip1 GOARCH=wasm`, and the executor streams whatever you
// print to stdout/stderr back to the user. The executor passes the user's
// command-line arguments verbatim as WASI argv, so `flag.CommandLine.Parse(os.Args)`
// reads them directly (note: there is no program name at os.Args[0]).
//
// This package wraps the raw host imports exported by the executor engine
// (internal/executor/debuglet/wasm/host_functions.go) so that debuglet authors
// do not have to deal with //go:wasmimport declarations or unsafe pointer math.
// Instead of juggling 32-bit memory offsets, you work with a small Conn type:
//
//	conn, err := debuglet.ConnectTCP("example.com:80")
//	if err != nil { ... }
//	defer conn.Close()
//	conn.Send([]byte("GET / HTTP/1.0\r\n\r\n"))
//	buf := make([]byte, 4096)
//	n, _ := conn.Receive(buf)
//	fmt.Println(string(buf[:n]))
//
// The package compiles to a no-op on non-wasip1 platforms so that the rest of
// the module still builds and tests on the host; the real implementation is in
// debuglet_wasip1.go.
package debuglet

import "errors"

// ErrConnect is returned when the host fails to establish a connection.
var ErrConnect = errors.New("debuglet: connect failed")

// transport identifies which family of host functions a Conn dispatches to.
type transport int

const (
	transportTCP transport = iota
	transportICMP4
)

// Conn is a connection handle returned by the Connect* helpers. It wraps the
// integer socket handle owned by the host and routes Send/Receive/Close to the
// correct host functions for its transport.
type Conn struct {
	handle int32
	tr     transport
}

// Handle returns the raw host socket handle. Most debuglets do not need this;
// it is exposed for diagnostics and advanced use.
func (c *Conn) Handle() int32 { return c.handle }

// ConnectTCP dials a plaintext TCP connection to addr ("host:port").
func ConnectTCP(addr string) (*Conn, error) { return dialTCP(addr, false) }

// ConnectTLS dials a TLS-over-TCP connection to addr ("host:port"). The host
// performs the TLS handshake; reads and writes carry plaintext application data.
func ConnectTLS(addr string) (*Conn, error) { return dialTCP(addr, true) }

// ConnectICMP4 opens a raw ICMPv4 socket to addr (an IPv4 address, no port).
// Use it to send/receive ICMP echo packets, e.g. for a ping probe.
func ConnectICMP4(addr string) (*Conn, error) { return dialICMP4(addr) }

// AcceptTCP blocks until the host's TCP listener accepts one inbound connection
// and returns it. Used by server-style debuglets (e.g. an echo or throughput
// sink). Requires the executor's TCP listener to be enabled.
func AcceptTCP() (*Conn, error) { return acceptTCP() }
