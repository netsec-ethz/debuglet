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

package debuglet_test

// The host transfer bound is part of the guest ABI; these tests cover what the
// SDK does with it, on the real engine and loopback peers the test owns.

import (
	"fmt"
	"net"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

const sdkIOFixture = "./pkg/debuglet/testdata/sdk_io"

func TestSDKTransferBound(t *testing.T) {
	wasm := buildGuest(t, sdkIOFixture)
	oversize := 2 * debuglet.MaxIOBytes

	t.Run("stream_write_delivers_every_byte", func(t *testing.T) {
		counted := make(chan int, 1)
		addr := startTCPTarget(t, func(conn net.Conn) { counted <- readAllFrom(conn) })
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"stream_write", addr}})
		requireSuccess(t, g)
		if got := report(t, counted, "the bytes it received"); got != oversize {
			t.Errorf("target received %d bytes, want %d: Write must carry a whole stream payload", got, oversize)
		}
		requireContains(t, g, "err=<nil>\n", "closed\n")
	})

	t.Run("oversized_datagram_is_refused", func(t *testing.T) {
		sizes := make(chan int, 4)
		addr := startUDPTarget(t, func(data []byte) []byte {
			sizes <- len(data)
			return nil
		})
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"datagram_write", addr}})
		requireSuccess(t, g)
		requireContains(t, g, "oversize refused=true toolarge=true\n", "bound err=<nil>\n")
		if got := report(t, sizes, "the datagram it received"); got != debuglet.MaxIOBytes {
			t.Errorf("target received a %d-byte datagram, want %d", got, debuglet.MaxIOBytes)
		}
		select {
		case extra := <-sizes:
			t.Errorf("target received a second datagram of %d bytes; the oversized one must not be sent", extra)
		default:
		}
	})

	t.Run("read_fills_at_most_the_bound", func(t *testing.T) {
		addr := startTCPTarget(t, func(conn net.Conn) {
			buf := make([]byte, 8)
			if _, err := conn.Read(buf); err != nil {
				return
			}
			reply := make([]byte, 2*debuglet.MaxIOBytes)
			for i := range reply {
				reply[i] = 'B'
			}
			conn.Write(reply)
			readAllFrom(conn)
		})
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"stream_read", addr}})
		requireSuccess(t, g)
		line := g.waitFor("stream_read ", 0)
		var buffer, read int
		if _, err := fmt.Sscanf(line, "stream_read buffer=%d n=%d", &buffer, &read); err != nil {
			t.Fatalf("unexpected line %q: %v", line, err)
		}
		if buffer != oversize {
			t.Errorf("guest used a %d-byte buffer, want %d", buffer, oversize)
		}
		if read <= 0 || read > debuglet.MaxIOBytes {
			t.Errorf("one read returned %d bytes, want between 1 and %d", read, debuglet.MaxIOBytes)
		}
	})
}
