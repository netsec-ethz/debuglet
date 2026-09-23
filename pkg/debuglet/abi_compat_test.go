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

// Guest ABI compatibility suite.
//
// The guest ABI is the frozen contract between a compiled guest and the host
// it runs on: the import names, their signatures, which side owns the memory
// behind a pointer, and the unit of every value that crosses the boundary.
// This suite holds that contract still in three ways:
//
//   - the frozen fixture in testdata/abi_v1 declares the imports itself, so it
//     keeps importing exactly what guests published under this ABI import,
//     whatever the SDK does later;
//   - the surface test compares both that fixture and the current SDK against
//     the frozen table below, so an added, removed, renamed or retyped import
//     is a failure that requires a new ABI identifier;
//   - the execution tests run the frozen fixture on the executor's real engine
//     and host imports against loopback peers the test owns, so a changed
//     ownership rule, error convention or transfer unit is a failure too.
//
// docs/GUESTS.md publishes the same contract and the compatibility matrix.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/buildinfo"
	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

const (
	// abiV1 is the identifier recorded in every installation manifest and
	// reported by the executor. A guest built for it runs on any host that
	// records the same identifier.
	abiV1 = "debuglet-go-wasi-imports-v1"

	// abiV1Fixture is the frozen guest for that identifier, as source built
	// with the pinned toolchain when the suite runs.
	abiV1Fixture = "./pkg/debuglet/testdata/abi_v1"
	// abiV1Compiled is that same guest as it was compiled and retained, so the
	// gate also runs a module that predates the host build under test.
	// abiV1Record carries its digest and the toolchain that produced it.
	abiV1Compiled = "testdata/abi_v1/abi_v1.wasm"
	abiV1Record   = "testdata/abi_v1/abi_v1.wasm.json"
	// sdkSurfaceFixture links the current SDK's complete host surface.
	sdkSurfaceFixture = "./pkg/debuglet/testdata/sdk_surface"

	// hostTransferBound is the number of bytes one host import call moves,
	// whatever the guest buffer's length is. It is part of the ABI.
	hostTransferBound = 8192

	// installedRootEnv points the installed-guest check at a verified
	// installation. The candidate pipeline sets it; a plain checkout does not.
	installedRootEnv = "DEBUGLET_GUEST_ABI_INSTALLED_ROOT"
)

// guestRecord is the record tracked beside a retained module: which ABI it was
// built for, which toolchain produced it, and what its bytes are.
type guestRecord struct {
	GuestABI  string `json:"guest_abi"`
	Toolchain string `json:"toolchain"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
}

// abiFunction is one entry of the frozen import table.
type abiFunction struct {
	params  []api.ValueType
	results []api.ValueType
}

func i32(n int) []api.ValueType {
	types := make([]api.ValueType, n)
	for i := range types {
		types[i] = api.ValueTypeI32
	}
	return types
}

// abiV1Imports is the complete "env" import surface of guest ABI v1. Pointers
// and lengths are 32-bit; a length is a count of bytes; a socket handle is a
// non-negative index the host assigns and the guest passes back unchanged.
//
// Changing any entry changes what a compiled guest links against and requires
// a new ABI identifier, because a guest built for the new table cannot run on
// a host that implements this one.
func abiV1Imports() map[string]abiFunction {
	return map[string]abiFunction{
		"connect_tcp":        {i32(2), i32(1)},
		"connect_tls":        {i32(2), i32(1)},
		"connect_udp":        {i32(2), i32(1)},
		"connect_icmp4":      {i32(2), i32(1)},
		"accept_tcp":         {i32(0), i32(1)},
		"get_tcp_addr":       {i32(2), i32(1)},
		"get_udp_addr":       {i32(2), i32(1)},
		"get_remote_addr":    {i32(3), i32(1)},
		"receive_tcp_data":   {i32(3), i32(1)},
		"receive_udp_data":   {i32(3), i32(1)},
		"receive_icmp4_data": {i32(3), i32(1)},
		"receive_udp_from":   {i32(5), i32(1)},
		"send_tcp_data":      {i32(3), i32(0)},
		"send_udp_data":      {i32(3), i32(0)},
		"send_icmp4_data":    {i32(3), i32(0)},
		"drain_connection":   {i32(1), i32(0)},
		"close_tcp":          {i32(1), i32(0)},
		"close_icmp4":        {i32(1), i32(0)},
	}
}

// TestGuestABIIdentifier pins the identifier that the packaging manifest and
// the executor report. Freezing it here means a breaking ABI change has to
// come with a new identifier and a new frozen fixture.
func TestGuestABIIdentifier(t *testing.T) {
	if artifact.GuestABI != abiV1 {
		t.Errorf("artifact.GuestABI = %q, want %q: a changed guest ABI needs a new identifier and its own frozen fixtures",
			artifact.GuestABI, abiV1)
	}
	if buildinfo.GuestABI != artifact.GuestABI {
		t.Errorf("buildinfo.GuestABI = %q, want %q: the reported and the recorded guest ABI must agree",
			buildinfo.GuestABI, artifact.GuestABI)
	}
	if filepath.Base(abiV1Fixture) != "abi_v1" {
		t.Errorf("frozen fixture %q does not name the ABI version it freezes", abiV1Fixture)
	}
	if debuglet.MaxIOBytes != hostTransferBound {
		t.Errorf("debuglet.MaxIOBytes = %d, want the frozen bound %d: the SDK and the ABI must agree on how much one call carries",
			debuglet.MaxIOBytes, hostTransferBound)
	}
	// Guest fixtures are compiled by the toolchain that runs this suite, so the
	// gate only means something when that toolchain is the pinned one.
	if runtime.Version() != artifact.Toolchain {
		t.Errorf("suite runs on %s, want the pinned %s: guests built here would not be the ones the release builds",
			runtime.Version(), artifact.Toolchain)
	}
}

// TestGuestABIV1ImportSurface freezes the import surface from both sides: the
// guest published under this ABI, and the SDK that produces new guests for it.
func TestGuestABIV1ImportSurface(t *testing.T) {
	for _, fixture := range []string{abiV1Fixture, sdkSurfaceFixture} {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			requireABIV1Surface(t, buildGuest(t, fixture))
		})
	}
}

// requireABIV1Imports fails when the module imports anything the frozen table
// does not contain, or contains at another signature. A guest need not use the
// whole table, so it does not require every entry; requireABIV1Surface does.
func requireABIV1Imports(t *testing.T, wasm []byte) map[string]abiFunction {
	t.Helper()
	want := abiV1Imports()
	got := importedEnvFunctions(t, wasm)
	for name, gotFn := range got {
		wantFn, ok := want[name]
		if !ok {
			t.Errorf("guest imports env.%s, which guest ABI %s does not contain: an added import requires a new identifier, because guests using it cannot run on hosts implementing %s",
				name, abiV1, abiV1)
			continue
		}
		if !sameTypes(gotFn.params, wantFn.params) || !sameTypes(gotFn.results, wantFn.results) {
			t.Errorf("env.%s has signature %s, want %s: a changed signature requires a new guest ABI identifier",
				name, signature(gotFn), signature(wantFn))
		}
	}
	return got
}

// requireABIV1Surface fails unless the module imports exactly this ABI.
func requireABIV1Surface(t *testing.T, wasm []byte) {
	t.Helper()
	got := requireABIV1Imports(t, wasm)
	for name := range abiV1Imports() {
		if _, ok := got[name]; !ok {
			t.Errorf("guest does not import env.%s: guest ABI %s requires it", name, abiV1)
		}
	}
}

// TestGuestABIV1OnCurrentHost rebuilds the frozen guest from source with the
// pinned toolchain and executes it on the current engine's real host imports.
func TestGuestABIV1OnCurrentHost(t *testing.T) {
	runABIV1Cases(t, buildGuest(t, abiV1Fixture))
}

// TestGuestABIV1CompiledGuestOnCurrentHost runs the retained module of this
// ABI: a guest that was compiled once and has not been rebuilt since. It is the
// case the gate exists for, so it runs the same cases as the source fixture.
func TestGuestABIV1CompiledGuestOnCurrentHost(t *testing.T) {
	wasm, record := retainedGuest(t)
	t.Logf("retained guest %s: %d bytes, built with %s", abiV1Compiled, record.Bytes, record.Toolchain)
	requireABIV1Surface(t, wasm)
	runABIV1Cases(t, wasm)
}

// retainedGuest reads the retained module and the record tracked beside it,
// and fails unless the two still describe each other.
func retainedGuest(t *testing.T) ([]byte, guestRecord) {
	t.Helper()
	data, err := os.ReadFile(abiV1Record)
	if err != nil {
		t.Fatalf("read the retained guest's record: %v", err)
	}
	var record guestRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		t.Fatalf("decode %s: %v", abiV1Record, err)
	}
	wasm, err := os.ReadFile(abiV1Compiled)
	if err != nil {
		t.Fatalf("read the retained guest: %v", err)
	}
	if record.GuestABI != abiV1 {
		t.Fatalf("retained guest records ABI %q, want %q", record.GuestABI, abiV1)
	}
	if record.Toolchain != artifact.Toolchain {
		t.Fatalf("retained guest was built with %q, want the pinned %q", record.Toolchain, artifact.Toolchain)
	}
	if record.Bytes != int64(len(wasm)) {
		t.Fatalf("retained guest is %d bytes, its record says %d", len(wasm), record.Bytes)
	}
	sum := sha256.Sum256(wasm)
	if digest := hex.EncodeToString(sum[:]); digest != record.SHA256 {
		t.Fatalf("retained guest digest %s does not match its record %s: rebuild it deliberately, with a new record",
			digest, record.SHA256)
	}
	return wasm, record
}

// runABIV1Cases executes every ABI v1 case against the current engine's real
// host imports. Each case owns its loopback peer.
func runABIV1Cases(t *testing.T, wasm []byte) {
	t.Helper()

	t.Run("connect_write_read_eof", func(t *testing.T) {
		request := make(chan string, 1)
		addr := startTCPTarget(t, func(conn net.Conn) {
			buf := make([]byte, 16)
			n, err := conn.Read(buf)
			if err != nil {
				request <- fmt.Sprintf("read error: %v", err)
				return
			}
			request <- string(buf[:n])
			conn.Write([]byte("PONG\n"))
		})
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"tcp_exchange", addr}})
		requireSuccess(t, g)
		if got := report(t, request, "the guest's request"); got != "PING\n" {
			t.Errorf("target received %q, want %q", got, "PING\n")
		}
		requireContains(t, g,
			"connected tcp handle=0\n",
			"remote="+addr+"\n",
			"sent=5\n",
			"recv eof\n",
			"total=5\n",
			"drained\n",
			"closed\n",
		)
	})

	t.Run("denied_destination_aborts_the_guest", func(t *testing.T) {
		addr := startTCPTarget(t, func(conn net.Conn) { readAllFrom(conn) })
		// The peer is reachable; the job's policy simply does not allow it.
		g := runGuest(t, wasm, hostOptions{addresses: []string{"127.0.0.2"}, args: []string{"tcp_connect_only", addr}})
		if g.err() == nil {
			t.Error("guest completed although its destination is outside the job's policy")
		}
		requireContains(t, g, "connecting tcp "+addr+"\n")
		requireAbsent(t, g, "connected tcp", "connect tcp rc=")
	})

	t.Run("refused_connection_aborts_the_guest", func(t *testing.T) {
		addr := closedTCPAddr(t)
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"tcp_connect_only", addr}})
		if g.err() == nil {
			t.Error("guest completed although its destination refused the connection")
		}
		requireContains(t, g, "connecting tcp "+addr+"\n")
		requireAbsent(t, g, "connected tcp", "connect tcp rc=")
	})

	t.Run("failed_tls_handshake_aborts_the_guest", func(t *testing.T) {
		addr := startTCPTarget(t, func(conn net.Conn) {
			buf := make([]byte, 64)
			conn.Read(buf)
		})
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"tls_connect_only", addr}})
		if g.err() == nil {
			t.Error("guest completed although the plaintext peer cannot complete a TLS handshake")
		}
		requireContains(t, g, "connecting tls "+addr+"\n")
		requireAbsent(t, g, "connected tls")
	})

	t.Run("execution_budget_ends_a_blocked_read", func(t *testing.T) {
		addr := startTCPTarget(t, func(conn net.Conn) { readAllFrom(conn) })
		const budget = 3 * time.Second
		g := startGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			args:      []string{"tcp_block", addr},
			budget:    budget,
		})
		g.waitFor("blocking", budget)
		if !g.wait(budget + 10*time.Second) {
			g.stop()
		}
		if err := g.err(); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("guest error = %v, want the execution budget's deadline", err)
		}
		requireAbsent(t, g, "returned n=")
	})

	t.Run("connected_udp_datagrams", func(t *testing.T) {
		received := make(chan string, 1)
		addr := startUDPTarget(t, func(data []byte) []byte {
			received <- string(data)
			return []byte("PONG")
		})
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"udp_echo", addr}})
		requireSuccess(t, g)
		if got := report(t, received, "the guest's datagram"); got != "PING" {
			t.Errorf("target received %q, want %q", got, "PING")
		}
		requireContains(t, g,
			"connected udp handle=0\n",
			"remote="+addr+"\n",
			"sent=4\n",
			"recv n=4 data=\"PONG\"\n",
			"closed\n",
		)
	})

	t.Run("tcp_listener", func(t *testing.T) {
		g := startGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			listenTCP: true,
			args:      []string{"listen_tcp"},
		})
		published := publishedAddr(t, g, "listening tcp ")
		conn, err := dialGuestListener(t, published, nil)
		if err != nil {
			t.Fatalf("dial the guest's listener at %s: %v", published, err)
		}
		if _, err := conn.Write([]byte("HELLO\n")); err != nil {
			t.Fatalf("write to the guest: %v", err)
		}
		reply := make([]byte, 5)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read the guest's reply: %v", err)
		}
		if string(reply) != "PONG\n" {
			t.Errorf("guest replied %q, want %q", reply, "PONG\n")
		}
		conn.Close()
		if !g.wait(15 * time.Second) {
			t.Fatalf("guest did not finish after the client closed; output:\n%s", g.output())
		}
		requireSuccess(t, g)
		requireContains(t, g,
			"connected accept handle=0\n",
			"recv n=6 data=\"HELLO\\n\"\n",
			"sent=5\n",
			"recv2 eof\n",
			"closed\n",
		)
	})

	t.Run("udp_listener", func(t *testing.T) {
		g := startGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			listenUDP: true,
			args:      []string{"listen_udp"},
		})
		published := publishedAddr(t, g, "listening udp ")
		sender, err := net.Dial("udp", published)
		if err != nil {
			t.Fatalf("dial the guest's UDP listener at %s: %v", published, err)
		}
		defer sender.Close()
		if _, err := sender.Write([]byte("DATAGRAM")); err != nil {
			t.Fatalf("send a datagram to the guest: %v", err)
		}
		if !g.wait(15 * time.Second) {
			t.Fatalf("guest did not report the datagram; output:\n%s", g.output())
		}
		requireSuccess(t, g)
		requireContains(t, g, "recvfrom n=8 data=\"DATAGRAM\" sender="+sender.LocalAddr().String()+"\n")
	})

	t.Run("listener_addresses_without_a_listener", func(t *testing.T) {
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"no_listener"}})
		requireSuccess(t, g)
		requireLines(t, g, "tcp_addr rc=-1", "udp_addr rc=-1")
	})

	t.Run("one_call_transfers_at_most_the_bound", func(t *testing.T) {
		counted := make(chan int, 1)
		addr := startTCPTarget(t, func(conn net.Conn) { counted <- readAllFrom(conn) })
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"io_bound", addr}})
		requireSuccess(t, g)
		if got := report(t, counted, "the bytes it received"); got != hostTransferBound {
			t.Errorf("one send call transferred %d bytes of a 16384-byte buffer, want %d: the transfer bound is part of the guest ABI",
				got, hostTransferBound)
		}
		requireContains(t, g, "offered=16384\n", "closed\n")
	})

	t.Run("wasi_clocks", func(t *testing.T) {
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"clock"}})
		requireSuccess(t, g)
		requireLines(t, g, "slept=true")
	})
}

// TestGuestABIInstalledGuests checks the guests shipped in a verified
// installation against the same frozen surface. The candidate pipeline points
// it at the installation it just verified; without that it has nothing to
// check.
func TestGuestABIInstalledGuests(t *testing.T) {
	root, selected := os.LookupEnv(installedRootEnv)
	if !selected {
		t.Skipf("%s is not set: this run is not checking an installed candidate", installedRootEnv)
	}
	if root == "" {
		t.Fatalf("%s is set but empty: the candidate pipeline must name the installation it verified", installedRootEnv)
	}
	manifest, err := artifact.Verify(root)
	if err != nil {
		t.Fatalf("verify the installation at %s: %v", root, err)
	}
	if manifest.GuestABI != abiV1 {
		t.Fatalf("installed manifest records guest ABI %q, want %q", manifest.GuestABI, abiV1)
	}
	for _, name := range []string{"demo.wasm", "hello.wasm"} {
		t.Run(name, func(t *testing.T) {
			wasm, err := os.ReadFile(filepath.Join(root, "share", "debuglet", name))
			if err != nil {
				t.Fatalf("read the installed guest: %v", err)
			}
			// An installed guest uses only the part of the ABI it needs.
			requireABIV1Imports(t, wasm)
		})
	}
}

// importedEnvFunctions compiles wasm and returns its "env" imports.
func importedEnvFunctions(t *testing.T, wasm []byte) map[string]abiFunction {
	t.Helper()
	ctx := context.Background()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer runtime.Close(ctx)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile module: %v", err)
	}
	defer compiled.Close(ctx)

	imports := make(map[string]abiFunction)
	for _, fn := range compiled.ImportedFunctions() {
		module, name, ok := fn.Import()
		if !ok || module != "env" {
			continue
		}
		imports[name] = abiFunction{params: fn.ParamTypes(), results: fn.ResultTypes()}
	}
	return imports
}

func sameTypes(got, want []api.ValueType) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// signature renders an ABI entry the way the frozen table describes it.
func signature(fn abiFunction) string {
	return "(" + strings.Join(names(fn.params), ",") + ") -> (" + strings.Join(names(fn.results), ",") + ")"
}

func names(types []api.ValueType) []string {
	rendered := make([]string, len(types))
	for i, t := range types {
		rendered[i] = api.ValueTypeName(t)
	}
	return rendered
}
