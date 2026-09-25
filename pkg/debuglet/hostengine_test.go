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

// This file is the shared harness for the guest compatibility and example
// suites. It compiles guests with the pinned toolchain for wasip1 and executes
// them on the executor's real engine and host imports, against loopback peers
// the tests own. Nothing here is a mock: the engine, the destination policy,
// the rate limiter and the listeners are the production implementations.

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	hostdebuglet "github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/fallback"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

const (
	// guestBuildTimeoutABI bounds one guest compilation, which may include a
	// cold wasip1 standard library build.
	guestBuildTimeoutABI = 180 * time.Second
	// defaultBudget is the execution budget of a guest that is expected to
	// finish on its own.
	defaultBudget = 30 * time.Second
	// joinTimeout bounds the wait for a guest after its runtime was closed.
	joinTimeout = 20 * time.Second
	// initTimeout bounds compilation and instantiation. It is deliberately not
	// the execution budget: compiling a guest in the interpreter takes as long
	// as the host is busy, and that time is not the job's to spend.
	initTimeout = 2 * time.Minute
	// peerDeadline bounds every loopback peer exchange, so a failing case
	// releases its helper goroutines instead of holding the test binary.
	peerDeadline = 30 * time.Second
	// loopback is the only destination these suites measure.
	loopback = "127.0.0.1"
)

var guestCache sync.Map // package path -> []byte

// repoRoot returns the checkout root: the package directory is pkg/debuglet.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(filepath.Dir(dir))
}

// buildGuest compiles pkgPath (relative to the checkout root) for wasip1 with
// the pinned toolchain and returns the module bytes. Compiled modules are
// cached for the lifetime of the test binary; none of them is committed.
func buildGuest(t *testing.T, pkgPath string) []byte {
	t.Helper()
	if cached, ok := guestCache.Load(pkgPath); ok {
		return cached.([]byte)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain is required to build guest %s: %v", pkgPath, err)
	}
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "guest.wasm")

	ctx, cancel := context.WithTimeout(context.Background(), guestBuildTimeoutABI)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-o", out, pkgPath)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	start := time.Now()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest %s (%s): %v\n%s", pkgPath, time.Since(start).Round(time.Millisecond), err, output)
	}
	wasm, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read guest %s: %v", pkgPath, err)
	}
	if len(wasm) == 0 {
		t.Fatalf("guest %s is empty", pkgPath)
	}
	t.Logf("built %s in %s (%d bytes)", pkgPath, time.Since(start).Round(time.Millisecond), len(wasm))
	guestCache.Store(pkgPath, wasm)
	return wasm
}

// hostOptions describes one job: its destination policy, its listeners, its
// guest arguments and its execution budget.
type hostOptions struct {
	addresses []string
	listenTCP bool
	listenUDP bool
	args      []string
	budget    time.Duration
	// operator overrides the executor's network policy. Nil runs the job
	// under the documented default policy, which is what an executor that
	// configures nothing applies.
	operator *netpolicy.Spec
}

// operatorSpec is the operator policy this job runs under. Without an explicit
// one it is the local profile: the documented defaults plus the local-target
// switch, because the shipped default denies the loopback peers these suites
// own.
func (o hostOptions) operatorSpec() netpolicy.Spec {
	if o.operator != nil {
		return *o.operator
	}
	spec := netpolicy.Defaults()
	spec.LocalTargets = true
	return spec
}

// guestRun is one running guest and its collected output.
type guestRun struct {
	t          *testing.T
	deb        *hostdebuglet.Debuglet
	cancel     context.CancelFunc
	cancelInit context.CancelFunc
	errCh      chan error
	closed     chan struct{}
	collect    sync.WaitGroup

	mu       sync.Mutex
	out      bytes.Buffer
	started  bool
	finished bool
	runErr   error

	stopOnce sync.Once
}

// startGuest registers and starts one guest exactly as the executor does:
// InitRuntime, then the requested listeners, then Run with verbatim arguments.
func startGuest(t *testing.T, wasm []byte, opts hostOptions) *guestRun {
	t.Helper()

	logger := zap.NewNop()
	id := uuid.New()
	schedule, err := tesla.NewKeySchedule(tesla.Config{
		Seed:        bytes.Repeat([]byte{0x42}, 32),
		Delay:       time.Second,
		ChainLength: 64,
	})
	if err != nil {
		t.Fatalf("tesla schedule: %v", err)
	}

	const capacity = app.Gigabit
	budget := opts.budget
	if budget == 0 {
		budget = defaultBudget
	}
	policy := scheduler.Policy{
		FloorBW:   0,
		CeilBW:    int64(capacity),
		Timeout:   budget,
		Addresses: opts.addresses,
		ListenTCP: opts.listenTCP,
		ListenUDP: opts.listenUDP,
	}

	limiter := app.NewLimiter(logger)
	limiter.SetExecutorCapacity(capacity)
	for _, addr := range opts.addresses {
		limiter.SetAddrCapacity(addr, capacity)
	}
	if err := limiter.InsertDebuglet(id, 0, capacity, opts.addresses); err != nil {
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

	var ports *socket.PortManager
	if opts.listenTCP || opts.listenUDP {
		ports, err = socket.NewPortManager(loopback, freePortSpec(t, 4))
		if err != nil {
			t.Fatalf("NewPortManager: %v", err)
		}
	}

	operator, err := netpolicy.Parse(opts.operatorSpec())
	if err != nil {
		t.Fatalf("netpolicy.Parse: %v", err)
	}
	deb := hostdebuglet.New(logger, id, "guest-compatibility", policy, operator, schedule, limiter, packetCount, nil, ports)
	initCtx, cancelInit := context.WithTimeout(context.Background(), initTimeout)
	g := &guestRun{t: t, deb: deb, cancelInit: cancelInit, errCh: make(chan error, 1)}
	t.Cleanup(g.stop)

	// Compilation runs before the budget starts, so a loaded host cannot spend
	// a guest's execution time on getting the module ready.
	if err := deb.InitRuntime(initCtx, wasm); err != nil {
		t.Fatalf("InitRuntime: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	g.cancel = cancel
	g.closed = make(chan struct{})

	// The executor closes a debuglet's runtime as soon as its execution budget
	// or a cancellation ends the job; that closure is what releases a guest
	// spinning on the processor or blocked in a host call.
	go func() {
		defer close(g.closed)
		<-ctx.Done()
		closeCtx, finish := context.WithTimeout(context.Background(), 10*time.Second)
		defer finish()
		_ = deb.Close(closeCtx)
	}()

	if opts.listenTCP || opts.listenUDP {
		startCtx, cancelStart := context.WithTimeout(ctx, 10*time.Second)
		defer cancelStart()
		req := hostdebuglet.StartServersReq{TCP: opts.listenTCP, UDP: opts.listenUDP}
		if err := deb.StartServers(startCtx, req); err != nil {
			t.Fatalf("StartServers: %v", err)
		}
	}

	outputCh := make(chan []byte, 256)
	g.collect.Add(1)
	go func() {
		defer g.collect.Done()
		for chunk := range outputCh {
			g.mu.Lock()
			g.out.Write(chunk)
			g.mu.Unlock()
		}
	}()
	g.mu.Lock()
	g.started = true
	g.mu.Unlock()
	go func() { g.errCh <- deb.Run(ctx, outputCh, opts.args) }()
	return g
}

// runGuest starts a guest and waits for it to finish on its own.
func runGuest(t *testing.T, wasm []byte, opts hostOptions) *guestRun {
	t.Helper()
	budget := opts.budget
	if budget == 0 {
		budget = defaultBudget
	}
	g := startGuest(t, wasm, opts)
	if !g.wait(budget + 5*time.Second) {
		g.stop()
		t.Fatalf("guest did not finish; output:\n%s", g.output())
	}
	return g
}

func (g *guestRun) output() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.out.String()
}

// err returns Run's result. It is only meaningful once the guest finished.
func (g *guestRun) err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.runErr
}

// wait reports whether Run returned within d, collecting its output first.
func (g *guestRun) wait(d time.Duration) bool {
	g.mu.Lock()
	finished, started := g.finished, g.started
	g.mu.Unlock()
	if finished || !started {
		return finished
	}
	select {
	case err := <-g.errCh:
		g.collect.Wait()
		g.mu.Lock()
		g.finished, g.runErr = true, err
		g.mu.Unlock()
		return true
	case <-time.After(d):
		return false
	}
}

// waitFor returns the first output line with the given prefix, or fails. A
// zero d checks the output already collected without waiting for more.
func (g *guestRun) waitFor(prefix string, d time.Duration) string {
	g.t.Helper()
	deadline := time.Now().Add(d)
	for {
		for _, line := range strings.Split(g.output(), "\n") {
			if strings.HasPrefix(line, prefix) {
				return line
			}
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("guest printed no line starting with %q within %s; output:\n%s", prefix, d, g.output())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stop ends the job and joins everything it owns. A guest that never reached
// its run context still has a runtime to release.
func (g *guestRun) stop() {
	g.stopOnce.Do(func() {
		if g.cancel != nil {
			g.cancel()
			select {
			case <-g.closed:
			case <-time.After(joinTimeout):
				g.t.Errorf("the runtime was not closed within %s", joinTimeout)
			}
		} else {
			closeCtx, finish := context.WithTimeout(context.Background(), 10*time.Second)
			defer finish()
			_ = g.deb.Close(closeCtx)
		}
		g.cancelInit()
		if !g.wait(joinTimeout) {
			g.t.Errorf("guest did not finish within %s after its runtime was closed", joinTimeout)
		}
	})
}

// requireSuccess fails the test unless the guest ran to completion. It stops
// the test, so a later wait for a loopback peer's report cannot hang on a guest
// that never got as far as connecting.
func requireSuccess(t *testing.T, g *guestRun) {
	t.Helper()
	if err := g.err(); err != nil {
		t.Fatalf("guest run: %v; output:\n%s", err, g.output())
	}
}

// report waits for one loopback peer's observation.
func report[T any](t *testing.T, ch chan T, what string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(peerDeadline):
		t.Fatalf("the loopback peer did not report %s within %s", what, peerDeadline)
	}
	var zero T
	return zero
}

func requireContains(t *testing.T, g *guestRun, want ...string) {
	t.Helper()
	got := g.output()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("guest output is missing %q; output:\n%s", w, got)
		}
	}
}

func requireAbsent(t *testing.T, g *guestRun, unwanted ...string) {
	t.Helper()
	got := g.output()
	for _, u := range unwanted {
		if strings.Contains(got, u) {
			t.Errorf("guest output unexpectedly contains %q; output:\n%s", u, got)
		}
	}
}

// requireLines fails unless the guest printed exactly these lines.
func requireLines(t *testing.T, g *guestRun, want ...string) {
	t.Helper()
	got := strings.Split(strings.TrimRight(g.output(), "\n"), "\n")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("guest output mismatch\n got:\n  %s\nwant:\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// freePortSpec reserves n loopback ports and releases them again, so the
// listener pool can bind them.
func freePortSpec(t *testing.T, n int) string {
	t.Helper()
	listeners := make([]net.Listener, 0, n)
	ports := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(loopback, "0"))
		if err != nil {
			t.Fatalf("reserve listener port: %v", err)
		}
		listeners = append(listeners, ln)
		_, port, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("split reserved address: %v", err)
		}
		ports = append(ports, port)
	}
	for _, ln := range listeners {
		ln.Close()
	}
	return strings.Join(ports, ",")
}

// publishedAddr waits for the guest's listener line and checks the address.
func publishedAddr(t *testing.T, g *guestRun, prefix string) string {
	t.Helper()
	published := g.waitFor(prefix, 30*time.Second)[len(prefix):]
	host, port := hostPort(t, published)
	if host != loopback || port == 0 {
		t.Fatalf("published listener address %q is not a loopback address with a port", published)
	}
	return published
}

// dialGuestListener connects to the guest's published listener from the given
// local address (nil for the default one) and bounds the exchange.
func dialGuestListener(t *testing.T, published string, from net.Addr) (net.Conn, error) {
	t.Helper()
	dialer := &net.Dialer{LocalAddr: from, Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", published)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(peerDeadline)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return conn, nil
}

// startTCPTarget serves handle on every accepted loopback connection and
// returns the target's "host:port". The listener is closed with the test.
func startTCPTarget(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(loopback, "0"))
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(peerDeadline))
				handle(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// closedTCPAddr returns a loopback address with nothing listening on it.
func closedTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(loopback, "0"))
	if err != nil {
		t.Fatalf("reserve closed address: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// startUDPTarget answers every datagram with handle's result. Returning nil
// sends nothing back.
func startUDPTarget(t *testing.T, handle func(data []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(loopback, "0"))
	if err != nil {
		t.Fatalf("listen UDP target: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		// Large enough for a datagram at the host transfer bound.
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if reply := handle(bytes.Clone(buf[:n])); reply != nil {
				_ = pc.SetWriteDeadline(time.Now().Add(peerDeadline))
				if _, err := pc.WriteTo(reply, from); err != nil {
					return
				}
			}
		}
	}()
	return pc.LocalAddr().String()
}

// readAllFrom reads until the peer closes and reports the byte count.
func readAllFrom(conn net.Conn) int {
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := conn.Read(buf)
		total += n
		if err != nil {
			return total
		}
	}
}

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port of %q: %v", addr, err)
	}
	return host, number
}
