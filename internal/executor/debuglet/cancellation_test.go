package debuglet_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/fallback"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"go.uber.org/zap"
)

func buildCancellationGuest(t *testing.T) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "cancellation.wasm")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-o", out, "./testdata/cancellation")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest: %v\n%s", err, output)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type observedCounter struct {
	ratelimit.PacketCount
	readEntered chan struct{}
	once        sync.Once
}

func (c *observedCounter) Attach(conn net.Conn, id uuid.UUID, addr string) (net.Conn, error) {
	wrapped, err := c.PacketCount.Attach(conn, id, addr)
	if err != nil {
		return wrapped, err
	}
	return &observedReadConn{Conn: wrapped, owner: c}, nil
}

type observedReadConn struct {
	net.Conn
	owner *observedCounter
}

func (c *observedReadConn) Read(b []byte) (int, error) {
	c.owner.once.Do(func() { close(c.owner.readEntered) })
	return c.Conn.Read(b)
}

func cancellationEngine(t *testing.T, data []byte) (*debuglet.Debuglet, <-chan struct{}) {
	t.Helper()
	logger := zap.NewNop()
	id := uuid.New()
	schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x71}, 32), Delay: time.Second, ChainLength: 64})
	if err != nil {
		t.Fatal(err)
	}
	limiter := app.NewLimiter(logger)
	limiter.SetExecutorCapacity(app.Gigabit)
	limiter.SetAddrCapacity("127.0.0.1", app.Gigabit)
	if err := limiter.InsertDebuglet(id, 0, app.Gigabit, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	pc, err := fallback.NewFallbackCount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if err := pc.SetExecLimit(id, app.Gigabit); err != nil {
		t.Fatal(err)
	}
	observed := &observedCounter{PacketCount: pc, readEntered: make(chan struct{})}
	operator, err := netpolicy.Parse(localProfile())
	if err != nil {
		t.Fatal(err)
	}
	deb := debuglet.New(logger, id, "cancel-fixture", scheduler.Policy{CeilBW: int64(app.Gigabit), Timeout: time.Minute, Addresses: []string{"127.0.0.1"}}, operator, schedule, limiter, observed, nil, nil)
	t.Cleanup(func() {
		if err := deb.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	initCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := deb.InitRuntime(initCtx, data); err != nil {
		t.Fatal(err)
	}
	return deb, observed.readEntered
}

func waitCanceledTest(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not join", what)
	}
}

// Cancellation must terminate real guest execution while the test-owned peer
// remains open. Closing the peer is emergency teardown, never positive evidence.
func TestWASICancellationCPUReadAndOutput(t *testing.T) {
	data := buildCancellationGuest(t)
	for _, mode := range []string{"cpu", "read", "output"} {
		t.Run(mode, func(t *testing.T) {
			deb, readEntered := cancellationEngine(t, data)
			cause := errors.New("operator cancellation")
			ctx, cancel := context.WithCancelCause(context.Background())
			output := make(chan []byte)
			args := []string{"-mode", mode}
			var listener net.Listener
			var peer net.Conn
			var peerMu sync.Mutex
			peerReady, peerDone := make(chan struct{}), make(chan struct{})
			var peerErr error
			if mode == "read" {
				var err error
				listener, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				args = append(args, "-addr", listener.Addr().String())
				go func() {
					defer close(peerDone)
					conn, err := listener.Accept()
					if err != nil {
						peerErr = err
						return
					}
					peerMu.Lock()
					peer = conn
					peerMu.Unlock()
					_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
					buf := make([]byte, len("READ READY\n"))
					_, err = io.ReadFull(conn, buf)
					if err != nil {
						peerErr = err
						return
					}
					if string(buf) != "READ READY\n" {
						peerErr = errors.New("wrong guest marker")
						return
					}
					close(peerReady)
				}()
			}
			runDone, closeDone := make(chan struct{}), make(chan struct{})
			var runErr, closeErr error
			go func() { defer close(runDone); runErr = deb.Run(ctx, output, args) }()
			go func() {
				defer close(closeDone)
				<-ctx.Done()
				closeCtx, finish := context.WithTimeout(context.Background(), scheduler.CleanupTimeout)
				defer finish()
				closeErr = deb.Close(closeCtx)
			}()
			t.Cleanup(func() {
				cancel(cause)
				if listener != nil {
					_ = listener.Close()
				}
				peerMu.Lock()
				if peer != nil {
					_ = peer.Close()
				}
				peerMu.Unlock()
				// Drain only after recording assertion failure: old blocked writers must
				// also be joined rather than abandoned by the regression harness.
				drainDone := make(chan struct{})
				go func() {
					for range output {
					}
					close(drainDone)
				}()
				waitCanceledTest(t, runDone, "Run teardown")
				waitCanceledTest(t, closeDone, "watcher teardown")
				waitCanceledTest(t, drainDone, "output teardown")
				if mode == "read" {
					waitCanceledTest(t, peerDone, "peer observer")
				}
			})
			if mode == "read" {
				select {
				case <-peerReady:
				case <-peerDone:
					t.Fatalf("peer failed: %v", peerErr)
				case <-time.After(5 * time.Second):
					t.Fatal("peer marker not observed")
				}
				waitCanceledTest(t, readEntered, "actual host Read entry")
			} else {
				select {
				case chunk, ok := <-output:
					if !ok || !strings.Contains(string(chunk), strings.ToUpper(mode)+" READY") {
						t.Fatalf("guest readiness %q", chunk)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("guest did not reach readiness")
				}
			}
			// A ready guest must still be running; output mode has no consumer after
			// its marker and therefore exercises the blocked WASI writer.
			select {
			case <-runDone:
				t.Fatalf("guest exited before cancellation: %v", runErr)
			default:
			}
			cancel(cause)
			waitCanceledTest(t, runDone, "canceled Run")
			waitCanceledTest(t, closeDone, "close watcher")
			if !errors.Is(runErr, cause) {
				t.Errorf("lost cancellation cause: %v", runErr)
			}
			if closeErr != nil {
				t.Errorf("resource closure: %v", closeErr)
			}
			if mode == "read" {
				waitCanceledTest(t, peerDone, "peer marker observer")
				if peerErr != nil {
					t.Fatal(peerErr)
				}
				peerMu.Lock()
				conn := peer
				peerMu.Unlock()
				// Our peer has not been closed; EOF proves the runtime closed its side.
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("guest-side socket survived: %d,%v", n, err)
				}
			}
		})
	}
}

// localProfile is the operator policy of an executor that measures against
// services on its own host. The shipped default denies loopback, so the
// fixtures that reach a loopback peer say so.
func localProfile() netpolicy.Spec {
	spec := netpolicy.Defaults()
	spec.LocalTargets = true
	return spec
}
