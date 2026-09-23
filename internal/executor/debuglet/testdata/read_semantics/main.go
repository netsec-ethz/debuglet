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

// Test fixture for TestReadSemanticsWASM. It is compiled with
// GOOS=wasip1 GOARCH=wasm by the test itself and is never built natively
// (Go ignores testdata directories).
//
// Protocol with the test-owned TCP server:
//
//  1. The guest connects and reads into a 4096-byte buffer until it has
//     accumulated exactly the expected short reply. Each read must return a
//     positive prefix without error; TCP may fragment the reply.
//  2. The guest writes ACK while the peer is still open. The server closes
//     only after receiving ACK (or after its own deadline, which the test
//     reports as a failed exchange).
//  3. The guest then observes a clean end of stream: Read reports io.EOF,
//     io.ReadAll terminates with zero bytes, and a further Read is io.EOF
//     again.
//
// Every step prints a line the test asserts on. A failure prints "RESULT FAIL"
// followed by the reason and exits with status 1.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

const (
	expectedReply = "pong:cycle2\n"
	ack           = "ACK\n"
	bufferSize    = 4096
)

var addr = flag.String("addr", "", "host:port of the test server")

func fail(format string, args ...any) {
	fmt.Printf("RESULT FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	// The executor passes user arguments verbatim as WASI argv, without a
	// program name, so os.Args is parsed as a whole.
	if err := flag.CommandLine.Parse(os.Args); err != nil {
		fail("flag parse: %v", err)
	}
	if *addr == "" {
		fail("missing -addr")
	}

	conn, err := debuglet.ConnectTCP(*addr)
	if err != nil {
		fail("connect %s: %v", *addr, err)
	}
	defer conn.Close()

	buf := make([]byte, bufferSize)
	var got []byte
	reads := 0
	for len(got) < len(expectedReply) {
		n, err := conn.Read(buf)
		reads++
		if err != nil {
			fail("read %d before ACK: n=%d err=%v got=%q", reads, n, err, got)
		}
		if n <= 0 {
			fail("read %d before ACK returned n=%d without error", reads, n)
		}
		got = append(got, buf[:n]...)
		if reads > len(expectedReply) {
			fail("too many reads (%d) accumulating %q", reads, got)
		}
	}
	if string(got) != expectedReply {
		fail("reply mismatch: got %q want %q", got, expectedReply)
	}
	fmt.Printf("REPLY OK bytes=%d reads=%d\n", len(got), reads)

	if err := conn.Write([]byte(ack)); err != nil {
		fail("write ACK: %v", err)
	}
	fmt.Println("ACK SENT")

	n, err := conn.Read(buf)
	if !errors.Is(err, io.EOF) || n != 0 {
		fail("read after ACK: n=%d err=%v want (0, io.EOF)", n, err)
	}
	fmt.Println("EOF OK")

	rest, err := io.ReadAll(conn)
	if err != nil {
		fail("ReadAll: %v", err)
	}
	if len(rest) != 0 {
		fail("ReadAll returned %d unexpected bytes", len(rest))
	}
	fmt.Printf("READALL OK bytes=%d\n", len(rest))

	n, err = conn.Read(buf)
	if !errors.Is(err, io.EOF) || n != 0 {
		fail("repeated read at EOF: n=%d err=%v want (0, io.EOF)", n, err)
	}
	fmt.Println("EOF AGAIN OK")

	fmt.Println("RESULT PASS")
}
