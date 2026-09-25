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

// read_contract is the guest fixture for TestSDKReadContractWASM. It is built
// with GOOS=wasip1 GOARCH=wasm by the test, executed under wazero with a
// scripted "env" host module, and prints one deterministic line per Read so
// the native test can assert the SDK's Read contract.
//
// The test passes the case name as the only argv element, mirroring the
// executor's verbatim WASI argv (no program name at os.Args[0]).
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

// bufSize is the nonempty buffer length used by every case. The host script
// asserts that receive imports are called with exactly this length.
const bufSize = 16

func main() {
	if len(os.Args) != 1 {
		fmt.Printf("usage: exactly one argv element (the case name), got %q\n", os.Args)
		os.Exit(2)
	}
	if err := run(os.Args[0]); err != nil {
		fmt.Printf("fixture error: %v\n", err)
		os.Exit(1)
	}
}

// report prints the outcome of one Read. eof is true only for the identical
// io.EOF sentinel that io.ReadAll and friends compare against; err is a fixed
// classification so the test never depends on incidental message text.
func report(label string, n int, err error, data []byte) {
	fmt.Printf("%s n=%d eof=%t err=%s data=%q\n", label, n, err == io.EOF, classify(err), data)
}

func classify(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, io.EOF):
		return "EOF"
	default:
		return "other"
	}
}

// readOnce performs one Read into a fresh bufSize buffer and reports it.
func readOnce(label string, c *debuglet.Conn) {
	buf := make([]byte, bufSize)
	n, err := c.Read(buf)
	var data []byte
	if n >= 0 && n <= len(buf) {
		data = buf[:n]
	}
	report(label, n, err, data)
}

// readEmpty performs both forms of an empty Read and reports them.
func readEmpty(label string, c *debuglet.Conn) {
	n, err := c.Read(nil)
	report(label+"_nil", n, err, nil)
	n, err = c.Read([]byte{})
	report(label+"_empty", n, err, nil)
}

func run(name string) error {
	var (
		conn *debuglet.Conn
		err  error
	)
	switch name {
	case "tcp_zero", "tcp_positive_then_eof", "tcp_negative", "tcp_oversized",
		"empty_reads_only", "empty_reads_after_eof":
		conn, err = debuglet.ConnectTCP("peer:1")
	case "tls_zero":
		conn, err = debuglet.ConnectTLS("peer:443")
	case "accepted_tcp_zero":
		conn, err = debuglet.AcceptTCP()
	case "udp_zero", "udp_oversized":
		conn, err = debuglet.ConnectUDP("peer:53")
	case "icmp_zero":
		conn, err = debuglet.ConnectICMP4("192.0.2.1")
	default:
		return fmt.Errorf("unknown case %q", name)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	switch name {
	case "tcp_positive_then_eof":
		readOnce("read1", conn)
		readOnce("read2", conn)
	case "empty_reads_only":
		readEmpty("read1", conn)
	case "empty_reads_after_eof":
		readEmpty("read1", conn)
		readOnce("read2", conn)
		readEmpty("read3", conn)
	default:
		readOnce("read1", conn)
	}
	return nil
}
