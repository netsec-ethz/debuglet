// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet_test

// Foreign-guest compatibility: the Rust bindings
// (examples/debuglets/rust/debuglet) and the C header
// (examples/debuglets/c/common/debuglet_api.h) declare part of guest ABI v1
// themselves. The retained guests under testdata/guest_rust and
// testdata/guest_c were compiled from them with the toolchains their records
// name; this suite checks their imports against the frozen table and runs them
// on the executor's real engine against loopback peers, with the same harness
// as the ABI v1 suite. The modules are committed because this suite does not
// install Rust or wasi-sdk; rebuild them deliberately, with a new record.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// foreignGuestRecord is the record tracked beside a retained foreign guest.
type foreignGuestRecord struct {
	GuestABI  string            `json:"guest_abi"`
	Language  string            `json:"language"`
	Toolchain string            `json:"toolchain"`
	Image     string            `json:"image"`
	Target    string            `json:"target"`
	Build     string            `json:"build"`
	SHA256    string            `json:"sha256"`
	Bytes     int64             `json:"bytes"`
	Sources   map[string]string `json:"sources"`
}

// foreignGuests are the retained guests, by language.
var foreignGuests = []struct {
	language string
	module   string
	record   string
}{
	{"rust", "testdata/guest_rust/guest_rust.wasm", "testdata/guest_rust/guest_rust.wasm.json"},
	{"c", "testdata/guest_c/guest_c.wasm", "testdata/guest_c/guest_c.wasm.json"},
}

// foreignGuestImports are the env imports both bindings declare and the
// fixtures use; a fixture that no longer imports them does not test the
// bindings.
var foreignGuestImports = []string{"connect_tcp", "accept_tcp", "receive_tcp_data", "send_tcp_data", "close_tcp"}

func TestForeignGuestsOnCurrentHost(t *testing.T) {
	for _, guest := range foreignGuests {
		t.Run(guest.language, func(t *testing.T) {
			wasm := retainedForeignGuest(t, guest.language, guest.module, guest.record)
			imports := requireABIV1Imports(t, wasm)
			for _, name := range foreignGuestImports {
				if _, ok := imports[name]; !ok {
					t.Errorf("%s guest does not import env.%s", guest.language, name)
				}
			}
			runForeignGuestCases(t, wasm)
		})
	}
}

// The source-build lane provides consumers made in empty directories from the
// packaged crate and copied header. Ordinary tests still run the retained guests.
func TestBuiltForeignConsumersOnCurrentHost(t *testing.T) {
	dir := os.Getenv("DEBUGLET_FOREIGN_CONSUMER_DIR")
	if dir == "" {
		t.Skip("run scripts/ci-guest-languages.sh to build fresh consumers")
	}
	for _, language := range []string{"c", "rust"} {
		t.Run(language, func(t *testing.T) {
			wasm, err := os.ReadFile(filepath.Join(dir, "consumer_"+language+".wasm"))
			if err != nil {
				t.Fatal(err)
			}
			requireABIV1Imports(t, wasm)
			runForeignGuestCases(t, wasm)
		})
	}
}

// retainedForeignGuest reads a retained module and fails unless its record
// still describes it.
func retainedForeignGuest(t *testing.T, language, module, recordPath string) []byte {
	t.Helper()
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read the retained guest's record: %v", err)
	}
	var record foreignGuestRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		t.Fatalf("decode %s: %v", recordPath, err)
	}
	wasm, err := os.ReadFile(module)
	if err != nil {
		t.Fatalf("read the retained guest: %v", err)
	}
	if record.GuestABI != abiV1 {
		t.Fatalf("%s records ABI %q, want %q", recordPath, record.GuestABI, abiV1)
	}
	if record.Language != language {
		t.Fatalf("%s records language %q, want %q", recordPath, record.Language, language)
	}
	if len(record.Sources) == 0 {
		t.Fatal("retained foreign guest has no source digests")
	}
	for path, want := range record.Sources {
		source, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(source)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s changed since the retained guest was built; rebuild the guest and its record", path)
		}
	}
	if record.Bytes != int64(len(wasm)) {
		t.Fatalf("retained guest is %d bytes, its record says %d", len(wasm), record.Bytes)
	}
	sum := sha256.Sum256(wasm)
	if digest := hex.EncodeToString(sum[:]); digest != record.SHA256 {
		t.Fatalf("retained guest digest %s does not match its record %s: rebuild it deliberately, with a new record",
			digest, record.SHA256)
	}
	t.Logf("retained guest %s: %d bytes, built with %s for %s", module, record.Bytes, record.Toolchain, record.Target)
	return wasm
}

// runForeignGuestCases runs the cases both fixtures implement. Each case owns
// its loopback peer.
func runForeignGuestCases(t *testing.T, wasm []byte) {
	t.Helper()

	t.Run("tcp_read_until_eof", func(t *testing.T) {
		// Longer than the guest's 4096-byte buffer and the host transfer
		// bound, so the guest needs several reads before the end of stream.
		payload := bytes.Repeat([]byte("debuglet"), 2500)
		addr := startTCPTarget(t, func(conn net.Conn) { conn.Write(payload) })
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"-addr", addr}})
		requireSuccess(t, g)
		requireLines(t, g,
			"connecting tcp "+addr,
			"connected",
			"eof",
			"total="+strconv.Itoa(len(payload)),
		)
	})

	t.Run("tcp_listener_echo", func(t *testing.T) {
		g := startGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			listenTCP: true,
			args:      []string{"-listen"},
		})
		g.waitFor("accepting", 30*time.Second)
		// The executor reports the listener's address to the submitter; the
		// bindings do not read it from inside the guest.
		endpoint := g.deb.TCPListenerEndpoint()
		if endpoint == "" {
			t.Fatal("the job has no TCP listener endpoint")
		}
		conn, err := dialGuestListener(t, endpoint, nil)
		if err != nil {
			t.Fatalf("dial the guest's listener at %s: %v", endpoint, err)
		}
		// Longer than the host transfer bound, so the echo needs the bindings'
		// send path to split it into several calls.
		message := bytes.Repeat([]byte("echo-me!"), 2500)
		if _, err := conn.Write(message); err != nil {
			t.Fatalf("write to the guest: %v", err)
		}
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("dialed connection is %T, not a TCP connection", conn)
		}
		if err := tcp.CloseWrite(); err != nil {
			t.Fatalf("half-close the connection: %v", err)
		}
		reply := make([]byte, len(message))
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read the guest's echo: %v", err)
		}
		if !bytes.Equal(reply, message) {
			t.Errorf("guest echoed %d bytes that differ from the %d bytes sent", len(reply), len(message))
		}
		conn.Close()
		if !g.wait(15 * time.Second) {
			t.Fatalf("guest did not finish after echoing; output:\n%s", g.output())
		}
		requireSuccess(t, g)
		requireLines(t, g, "accepting", "echoed n="+strconv.Itoa(len(message)), "closed")
	})

	t.Run("refused_connection_aborts_the_guest", func(t *testing.T) {
		addr := closedTCPAddr(t)
		g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"-addr", addr}})
		if g.err() == nil {
			t.Error("guest completed although its destination refused the connection")
		}
		// The host aborts the guest inside connect_tcp: the documented -1
		// return of earlier bindings never reaches the guest.
		requireLines(t, g, "connecting tcp "+addr)
	})
}
