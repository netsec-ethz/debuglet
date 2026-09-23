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

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/fallback"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// These constants mirror testdata/read_semantics/main.go.
const (
	readSemanticsReply = "pong:cycle2\n"
	readSemanticsACK   = "ACK\n"

	// readSemanticsBuildTimeout bounds guest compilation, which may include a
	// cold wasip1 standard library build.
	readSemanticsBuildTimeout = 90 * time.Second
	// readSemanticsExchangeTimeout bounds the whole network exchange. The peer
	// closes its side when it expires; that closure is reported as a failed
	// exchange, never as a successful short read.
	readSemanticsExchangeTimeout = 10 * time.Second
	// readSemanticsJoinTimeout bounds the wait for helper goroutines after a
	// failure has already been detected.
	readSemanticsJoinTimeout = 15 * time.Second
)

// buildReadSemanticsGuest compiles the fixture from the current checkout into
// dir and returns the module bytes. Missing Go or a compilation failure fails
// the test; the fixture is never committed as a binary.
func buildReadSemanticsGuest(t *testing.T, dir string) []byte {
	t.Helper()

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain is required to build the WASM fixture: %v", err)
	}

	out := filepath.Join(dir, "read_semantics.wasm")
	ctx, cancel := context.WithTimeout(context.Background(), readSemanticsBuildTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, goBin, "build", "-mod=readonly", "-o", out, "./testdata/read_semantics")
	cmd.Env = append(os.Environ(),
		"GOOS=wasip1",
		"GOARCH=wasm",
		"CGO_ENABLED=0",
		"GOTOOLCHAIN=local",
	)
	start := time.Now()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building WASM fixture failed after %s: %v\n%s", time.Since(start), err, output)
	}
	t.Logf("built WASM fixture in %s", time.Since(start))

	wasmBytes, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading WASM fixture: %v", err)
	}
	if len(wasmBytes) == 0 {
		t.Fatal("WASM fixture is empty")
	}
	return wasmBytes
}

// peerResult is what the test-owned TCP server observed.
type peerResult struct {
	// ackBeforeClose is true only when the guest's ACK arrived while the peer
	// was still open. A deadline-triggered close leaves it false.
	ackBeforeClose bool
	err            error
}

// serveShortReply accepts one connection, sends the short reply, waits for
// the guest's ACK and only then closes. The result is delivered on the
// returned channel exactly once.
func serveShortReply(ln net.Listener, deadline time.Time) <-chan peerResult {
	resultCh := make(chan peerResult, 1)
	go func() {
		var res peerResult
		defer func() { resultCh <- res }()

		conn, err := ln.Accept()
		if err != nil {
			res.err = fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(deadline); err != nil {
			res.err = fmt.Errorf("set deadline: %w", err)
			return
		}

		if _, err := conn.Write([]byte(readSemanticsReply)); err != nil {
			res.err = fmt.Errorf("write reply: %w", err)
			return
		}

		ackBuf := make([]byte, len(readSemanticsACK))
		if _, err := io.ReadFull(conn, ackBuf); err != nil {
			res.err = fmt.Errorf("waiting for ACK before closing: %w", err)
			return
		}
		if string(ackBuf) != readSemanticsACK {
			res.err = fmt.Errorf("unexpected ACK payload %q", ackBuf)
			return
		}
		res.ackBeforeClose = true
	}()
	return resultCh
}

// TestReadSemanticsWASM drives the real engine (Debuglet.New, InitRuntime,
// Run) with the production host functions and the fallback rate limiter
// against a loopback TCP peer. It proves that a short reply is delivered to
// the guest while the peer is still open and that peer closure becomes a
// normal io.EOF inside the guest.
func TestReadSemanticsWASM(t *testing.T) {
	wasmBytes := buildReadSemanticsGuest(t, t.TempDir())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	exchangeDeadline := time.Now().Add(readSemanticsExchangeTimeout)
	peerCh := serveShortReply(ln, exchangeDeadline)

	// Engine setup mirrors the executor's registerDebuglet path without a
	// dispatcher, database, payment, SCION, public host or StartServers.
	logger := zap.NewNop()
	id := uuid.New()
	seed := bytes.Repeat([]byte{0x42}, 32)
	schedule, err := tesla.NewKeySchedule(tesla.Config{
		Seed:        seed,
		Delay:       time.Second,
		ChainLength: 64,
	})
	if err != nil {
		t.Fatalf("tesla schedule: %v", err)
	}

	const highLimit = app.Gigabit
	addresses := []string{"127.0.0.1"}
	policy := scheduler.Policy{
		FloorBW:   0,
		CeilBW:    int64(highLimit),
		Timeout:   readSemanticsExchangeTimeout,
		Addresses: addresses,
	}

	limiter := app.NewLimiter(logger)
	limiter.SetExecutorCapacity(highLimit)
	for _, a := range addresses {
		limiter.SetAddrCapacity(a, highLimit)
	}
	if err := limiter.InsertDebuglet(id, 0, highLimit, addresses); err != nil {
		t.Fatalf("InsertDebuglet: %v", err)
	}

	packetCount, err := fallback.NewFallbackCount()
	if err != nil {
		t.Fatalf("NewFallbackCount: %v", err)
	}
	execLimit, _, err := limiter.GetExecLimit(id)
	if err != nil {
		t.Fatalf("GetExecLimit: %v", err)
	}
	if err := packetCount.SetExecLimit(id, execLimit); err != nil {
		t.Fatalf("SetExecLimit: %v", err)
	}

	operator, err := netpolicy.Parse(localProfile())
	if err != nil {
		t.Fatalf("netpolicy.Parse: %v", err)
	}
	deb := debuglet.New(logger, id, "read-semantics-test", policy, operator, schedule, limiter, packetCount, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := deb.InitRuntime(ctx, wasmBytes); err != nil {
		deb.Close(ctx)
		t.Fatalf("InitRuntime: %v", err)
	}

	runCtx, cancelRun := context.WithDeadline(ctx, exchangeDeadline.Add(2*time.Second))
	defer cancelRun()

	// Drain Run's output concurrently; Run closes the channel when finished.
	outputCh := make(chan []byte, 256)
	var (
		outputMu  sync.Mutex
		output    bytes.Buffer
		collector sync.WaitGroup
	)
	collector.Add(1)
	go func() {
		defer collector.Done()
		for chunk := range outputCh {
			outputMu.Lock()
			output.Write(chunk)
			outputMu.Unlock()
		}
	}()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- deb.Run(runCtx, outputCh, []string{"-addr", addr})
	}()

	// Release everything in a bounded way after the assertions, or on the
	// failure paths below. Peer closure comes first so a host read blocked
	// on the socket returns before HostConn is closed.
	var runErr error
	runFinished := false
	cleanup := func() {
		ln.Close()
		cancelRun()
		if !runFinished {
			select {
			case runErr = <-runErrCh:
				runFinished = true
			case <-time.After(readSemanticsJoinTimeout):
				t.Errorf("Run did not return within %s after cancellation", readSemanticsJoinTimeout)
			}
		}
		if runFinished {
			collector.Wait()
		}
		closeCtx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelClose()
		deb.Close(closeCtx)
	}

	select {
	case runErr = <-runErrCh:
		runFinished = true
	case <-time.After(readSemanticsExchangeTimeout + 5*time.Second):
		cleanup()
		t.Fatalf("guest did not finish within %s; peer: %+v; output:\n%s",
			readSemanticsExchangeTimeout+5*time.Second, <-peerCh, snapshot(&outputMu, &output))
	}

	var peer peerResult
	select {
	case peer = <-peerCh:
	case <-time.After(readSemanticsJoinTimeout):
		cleanup()
		t.Fatalf("peer did not report within %s; output:\n%s", readSemanticsJoinTimeout, snapshot(&outputMu, &output))
	}
	cleanup()

	got := snapshot(&outputMu, &output)
	t.Logf("guest output:\n%s", got)

	if runErr != nil {
		t.Errorf("Run returned error: %v", runErr)
	}
	if peer.err != nil {
		t.Errorf("peer exchange failed: %v", peer.err)
	}
	if !peer.ackBeforeClose {
		t.Errorf("peer closed before receiving the guest's ACK: the short reply was not delivered while the peer was open")
	}

	for _, want := range []string{
		"REPLY OK bytes=" + fmt.Sprint(len(readSemanticsReply)),
		"ACK SENT",
		"EOF OK",
		"READALL OK bytes=0",
		"EOF AGAIN OK",
		"RESULT PASS",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("guest output missing %q", want)
		}
	}
	if strings.Contains(got, "RESULT FAIL") {
		t.Errorf("guest reported failure")
	}
	if errors.Is(runErr, context.DeadlineExceeded) {
		t.Errorf("execution hit the deadline instead of completing the exchange")
	}
}

func snapshot(mu *sync.Mutex, buf *bytes.Buffer) string {
	mu.Lock()
	defer mu.Unlock()
	return buf.String()
}
