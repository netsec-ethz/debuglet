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

// The published Go examples are covered here: every one of them compiles with
// the pinned toolchain, and every supported one runs on the real engine
// against a loopback peer this test owns. docs/GUESTS.md and
// examples/debuglets/go/README.md publish the same set.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// goExample is one published example. Supported examples have an execution
// test below; the others are references that only have to keep compiling,
// because they need privileges or a destination this test cannot own.
type goExample struct {
	name      string
	supported bool
	// reason explains a reference example's exclusion.
	reason string
}

var goExamples = []goExample{
	{name: "helloworld", supported: true},
	{name: "hello-local", supported: true},
	{name: "demo", supported: true},
	{name: "latency", supported: true},
	{name: "http_get", supported: true},
	{name: "dns", supported: true},
	{name: "throughput", supported: true},
	{name: "listen_tcp", supported: true},
	{name: "listen_udp", supported: true},
	{name: "send_udp", supported: true},
	{name: "loop", supported: true},
	{name: "ping", reason: "ICMP needs an executor allowed to open raw sockets"},
	{name: "send_tcp", reason: "raw host-import reference for the SDK's calling convention"},
	{name: "download", reason: "raw host-import reference that needs an HTTP target to download from"},
}

func examplePath(name string) string { return "./examples/debuglets/go/" + name }

// TestGoExamplesAreListed keeps the table above complete. A sample that is
// added without an entry is a sample nothing builds or runs.
func TestGoExamplesAreListed(t *testing.T) {
	listed := make(map[string]bool, len(goExamples))
	for _, example := range goExamples {
		listed[example.name] = true
	}
	root := filepath.Join(repoRoot(t), "examples", "debuglets", "go")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read the Go example directory: %v", err)
	}
	directories := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		directories++
		if !listed[entry.Name()] {
			t.Errorf("%s is published but not in the example table: list it as supported with an execution test, or as a reference with a reason", entry.Name())
		}
		delete(listed, entry.Name())
	}
	for name := range listed {
		t.Errorf("the example table lists %s, which is not a directory under examples/debuglets/go", name)
	}
	if directories == 0 {
		t.Fatalf("no example directories under %s", root)
	}
}

// TestGoExamplesCompile builds every published Go example for wasip1 with the
// pinned toolchain. The builds run concurrently and are reused by the
// execution tests below.
func TestGoExamplesCompile(t *testing.T) {
	for _, example := range goExamples {
		t.Run(example.name, func(t *testing.T) {
			t.Parallel()
			if !example.supported && example.reason == "" {
				t.Fatalf("example %s is not supported and gives no reason", example.name)
			}
			buildGuest(t, examplePath(example.name))
		})
	}
}

func TestGoExamplesOnCurrentHost(t *testing.T) {
	t.Run("helloworld", func(t *testing.T) {
		g := runGuest(t, buildGuest(t, examplePath("helloworld")), hostOptions{})
		requireSuccess(t, g)
		requireLines(t, g, "Hello from Debuglet! (Go)")
	})

	t.Run("hello-local_echoes_its_arguments", func(t *testing.T) {
		g := runGuest(t, buildGuest(t, examplePath("hello-local")), hostOptions{args: []string{"-addr", "example"}})
		requireSuccess(t, g)
		requireLines(t, g, "Hello from Debuglet!", "-addr", "example")
	})

	t.Run("demo_completes_the_nonce_exchange", func(t *testing.T) {
		const nonce = "0123456789abcdef0123456789abcdef"
		addr := startTCPTarget(t, func(conn net.Conn) {
			if _, err := conn.Write([]byte("DEBUGLET/1 " + nonce + "\n")); err != nil {
				return
			}
			ack := make([]byte, len("ACK "+nonce+"\n"))
			io.ReadFull(conn, ack)
		})
		g := runGuest(t, buildGuest(t, examplePath("demo")), hostOptions{
			addresses: []string{loopback},
			args:      []string{addr, nonce},
		})
		requireSuccess(t, g)
		requireLines(t, g, "DEBUGLET_DEMO_OK "+nonce)
	})

	t.Run("latency_reports_every_round_trip", func(t *testing.T) {
		addr := startTCPTarget(t, func(conn net.Conn) {
			buf := make([]byte, 512)
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			conn.Write(buf[:n])
		})
		g := runGuest(t, buildGuest(t, examplePath("latency")), hostOptions{
			addresses: []string{loopback},
			args:      []string{"-addr", addr, "-count", "2"},
		})
		requireSuccess(t, g)
		requireContains(t, g,
			"target="+addr+" count=2\n",
			"rtt seq=0 bytes=5 ms=",
			"rtt seq=1 bytes=5 ms=",
			"summary samples=2 min_ms=",
		)
	})

	t.Run("http_get_reads_a_whole_response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "hello\n")
		}))
		t.Cleanup(server.Close)
		addr := server.Listener.Addr().String()
		g := runGuest(t, buildGuest(t, examplePath("http_get")), hostOptions{
			addresses: []string{loopback},
			args:      []string{"-addr", addr, "-path", "/"},
		})
		requireSuccess(t, g)
		requireContains(t, g,
			"GET / from "+addr+"\n",
			"status=HTTP/1.0 200 OK\n",
			"body_bytes=6\n",
		)
	})

	t.Run("dns_reads_an_a_record", func(t *testing.T) {
		addr := startUDPTarget(t, dnsAnswer([4]byte{192, 0, 2, 7}, 60))
		g := runGuest(t, buildGuest(t, examplePath("dns")), hostOptions{
			addresses: []string{loopback},
			args:      []string{"-addr", addr, "-name", "example.org"},
		})
		requireSuccess(t, g)
		requireContains(t, g,
			"query name=example.org type=A server="+addr+"\n",
			"answer a=192.0.2.7 ttl=60\n",
			"answers=1 elapsed_ms=",
		)
	})

	t.Run("throughput_sends_for_its_duration", func(t *testing.T) {
		counted := make(chan int, 1)
		addr := startTCPTarget(t, func(conn net.Conn) { counted <- readAllFrom(conn) })
		g := runGuest(t, buildGuest(t, examplePath("throughput")), hostOptions{
			addresses: []string{loopback},
			args:      []string{"-addr", addr, "-secs", "1", "-chunk", "1024"},
			budget:    30 * time.Second,
		})
		requireSuccess(t, g)
		requireContains(t, g, "[*] throughput: sending to "+addr, "[+] sent ")
		if got := report(t, counted, "the bytes it received"); got == 0 {
			t.Error("the sink received no bytes")
		}
	})

	t.Run("listen_tcp_serves_one_client", func(t *testing.T) {
		g := startGuest(t, buildGuest(t, examplePath("listen_tcp")), hostOptions{
			addresses: []string{loopback},
			listenTCP: true,
			args:      []string{"-count", "1"},
		})
		conn, err := dialGuestListener(t, publishedAddr(t, g, "listening on "), nil)
		if err != nil {
			t.Fatalf("dial the guest's listener: %v", err)
		}
		if _, err := conn.Write([]byte("HELLO\n")); err != nil {
			t.Fatalf("write to the guest: %v", err)
		}
		echo := make([]byte, 6)
		if _, err := io.ReadFull(conn, echo); err != nil {
			t.Fatalf("read the guest's echo: %v", err)
		}
		if string(echo) != "HELLO\n" {
			t.Errorf("guest echoed %q, want %q", echo, "HELLO\n")
		}
		if !g.wait(15 * time.Second) {
			t.Fatalf("guest did not finish; output:\n%s", g.output())
		}
		requireSuccess(t, g)
		requireContains(t, g, "client seq=0 remote=", "received seq=0 bytes=6\n", "served=1\n")
	})

	t.Run("listen_udp_reports_one_datagram", func(t *testing.T) {
		g := startGuest(t, buildGuest(t, examplePath("listen_udp")), hostOptions{
			addresses: []string{loopback},
			listenUDP: true,
			args:      []string{"-count", "1"},
		})
		published := publishedAddr(t, g, "listening on ")
		sender, err := net.Dial("udp", published)
		if err != nil {
			t.Fatalf("dial the guest's UDP listener: %v", err)
		}
		defer sender.Close()
		if _, err := sender.Write([]byte("DATAGRAM")); err != nil {
			t.Fatalf("send a datagram: %v", err)
		}
		if !g.wait(15 * time.Second) {
			t.Fatalf("guest did not finish; output:\n%s", g.output())
		}
		requireSuccess(t, g)
		requireContains(t, g,
			"received seq=0 bytes=8 from="+sender.LocalAddr().String()+"\n",
			"received=1\n",
		)
	})

	t.Run("send_udp_reports_what_it_sent", func(t *testing.T) {
		arrived := make(chan int, 8)
		addr := startUDPTarget(t, func(data []byte) []byte {
			select {
			case arrived <- len(data):
			default:
			}
			return nil
		})
		g := runGuest(t, buildGuest(t, examplePath("send_udp")), hostOptions{
			addresses: []string{loopback},
			args:      []string{"-addr", addr, "-count", "3", "-payload", "hi"},
		})
		requireSuccess(t, g)
		requireContains(t, g, "sent=3 bytes=6 to="+addr+"\n")
		if size := report(t, arrived, "a datagram"); size != 2 {
			t.Errorf("target received a %d-byte datagram, want 2", size)
		}
	})

	t.Run("a_refused_destination_ends_the_job", func(t *testing.T) {
		addr := closedTCPAddr(t)
		g := runGuest(t, buildGuest(t, examplePath("latency")), hostOptions{
			addresses: []string{loopback},
			args:      []string{"-addr", addr, "-count", "1"},
		})
		if g.err() == nil {
			t.Error("the job succeeded although its destination refused the connection")
		}
		requireContains(t, g, "target="+addr+" count=1\n")
		requireAbsent(t, g, "rtt seq=0", "summary")
	})

	t.Run("loop_is_ended_by_the_execution_budget", func(t *testing.T) {
		const budget = 3 * time.Second
		g := startGuest(t, buildGuest(t, examplePath("loop")), hostOptions{budget: budget})
		if !g.wait(budget + 10*time.Second) {
			g.stop()
		}
		if err := g.err(); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("guest error = %v, want the execution budget's deadline", err)
		}
	})
}

// dnsAnswer replies to a query with one A record for the question's name.
func dnsAnswer(ip [4]byte, ttl uint32) func([]byte) []byte {
	return func(query []byte) []byte {
		if len(query) < 12 {
			return nil
		}
		reply := append([]byte(nil), query...)
		reply[2], reply[3] = 0x81, 0x80 // response, recursion available, no error
		reply[6], reply[7] = 0x00, 0x01 // one answer record
		return append(reply, []byte{
			0xc0, 0x0c, // the question's name
			0x00, 0x01, // type A
			0x00, 0x01, // class IN
			byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
			0x00, 0x04, // four bytes of record data
			ip[0], ip[1], ip[2], ip[3],
		}...)
	}
}
