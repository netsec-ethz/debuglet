// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connectivity"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// Skip compilation while retaining real run listener policy, binding and cleanup.
type listenerSetupRuntime struct {
	*debuglet.Debuglet
	initialized chan struct{}
	calls       atomic.Int32
	start       func(context.Context, debuglet.StartServersReq) error
}

func (r *listenerSetupRuntime) InitRuntime(ctx context.Context, _ []byte) error {
	close(r.initialized)
	return ctx.Err()
}

func (r *listenerSetupRuntime) StartServers(ctx context.Context, req debuglet.StartServersReq) error {
	r.calls.Add(1)
	if r.start != nil {
		return r.start(ctx, req)
	}
	return r.Debuglet.StartServers(ctx, req)
}

func listenerSetupFixture(t *testing.T, policy config.PolicyConfig) (*Executor, *listenerSetupRuntime, scheduler.Spec) {
	t.Helper()
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	e.portManager, err = socket.NewPortManager("127.0.0.1", strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	e.cfg.Connectivity.Listeners = true
	spec := operationSpec()
	spec.Policy.ListenTCP = true
	operator, err := policy.Compile()
	if err != nil {
		t.Fatal(err)
	}
	runtime := &listenerSetupRuntime{initialized: make(chan struct{}), Debuglet: debuglet.New(e.logger,
		spec.DebugletID, spec.TransactionID, spec.Policy, operator, e.teslaSchedule, e.limiter,
		e.packetCount, e.iface, e.portManager, socket.NewBudget(socket.DefaultLimits(), e.socketBudget))}
	t.Cleanup(func() {
		if err := runtime.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return e, runtime, spec
}

func holdListenerProof(t *testing.T, e *Executor) func() {
	t.Helper()
	vantage := &pb.VantagePointReport{Listeners: []string{"tcp"}}
	finish := e.probeConnectivity(t.Context(), operationBinding(), vantage)
	t.Cleanup(finish)
	if vantage.Connectivity == nil || len(vantage.Connectivity.Listeners) != 1 {
		t.Fatal("missing real proof listener")
	}
	proof := vantage.Connectivity.Listeners[0]
	if err := connectivity.Check(t.Context(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(proof.Port))), proof.Token); err != nil {
		t.Fatal("proof listener did not authenticate:", err)
	}
	return finish
}

func TestListenerSetupWaitsForProof(t *testing.T) {
	e, runtime, spec := listenerSetupFixture(t, config.PolicyConfig{})
	finish := holdListenerProof(t, e)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.initializeDebuglet(ctx, spec, runtime) }()
	if !operationAwait(t, runtime.initialized, "runtime initialization") {
		return
	}
	select {
	case err := <-done:
		t.Fatalf("run raced the held proof listener: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	finish()
	finish() // Repeated cleanup must not release somebody else's gate token.
	select {
	case err := <-done:
		if err != nil || runtime.calls.Load() != 1 || runtime.TCPListenerEndpoint() == "" {
			t.Fatalf("run did not bind once after proof cleanup: calls=%d err=%v", runtime.calls.Load(), err)
		}
	case <-time.After(operationTestBound):
		t.Fatal("run did not resume after proof cleanup")
	}
}

func TestListenerSetupCancellationWhileProofHeld(t *testing.T) {
	e, runtime, spec := listenerSetupFixture(t, config.PolicyConfig{})
	finish := holdListenerProof(t, e)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.initializeDebuglet(ctx, spec, runtime) }()
	if !operationAwait(t, runtime.initialized, "runtime initialization") {
		return
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || runtime.calls.Load() != 0 {
			t.Fatalf("canceled waiter called listener setup: calls=%d err=%v", runtime.calls.Load(), err)
		}
	case <-time.After(operationTestBound):
		t.Fatal("cancellation waited for proof cleanup")
	}
	finish()
}

func TestListenerSetupBypassAndErrors(t *testing.T) {
	for _, scion := range []bool{false, true} {
		t.Run("bypass-scion-"+strconv.FormatBool(scion), func(t *testing.T) {
			e, runtime, spec := listenerSetupFixture(t, config.PolicyConfig{})
			holdListenerProof(t, e)
			spec.Policy.ListenTCP, spec.Policy.ListenSCION = false, scion
			runtime.start = func(ctx context.Context, _ debuglet.StartServersReq) error { return ctx.Err() }
			ctx, cancel := context.WithTimeout(t.Context(), operationTestBound)
			defer cancel()
			if err := e.initializeDebuglet(ctx, spec, runtime); err != nil || runtime.calls.Load() != 1 {
				t.Fatalf("unrelated setup waited for TCP proof: calls=%d err=%v", runtime.calls.Load(), err)
			}
		})
	}
	for _, denied := range []bool{false, true} {
		t.Run("error-policy-"+strconv.FormatBool(denied), func(t *testing.T) {
			allowed := !denied
			e, runtime, spec := listenerSetupFixture(t, config.PolicyConfig{Inbound: &allowed})
			want := errors.New("listener control refused")
			if denied {
				want = netpolicy.ErrTransportUnavailable
			} else {
				runtime.start = func(context.Context, debuglet.StartServersReq) error { return want }
			}
			if err := e.initializeDebuglet(t.Context(), spec, runtime); !errors.Is(err, want) || runtime.calls.Load() != 1 {
				t.Fatalf("listener failure changed or retried: calls=%d err=%v", runtime.calls.Load(), err)
			}
			select {
			case e.listenerSetup <- struct{}{}:
				<-e.listenerSetup
			default:
				t.Fatal("failed setup retained the gate")
			}
		})
	}
}

func TestConnectivitySkipsBusyListenerSetup(t *testing.T) {
	e, runtime, spec := listenerSetupFixture(t, config.PolicyConfig{})
	entered, release := make(chan struct{}), make(chan struct{})
	runtime.start = func(ctx context.Context, req debuglet.StartServersReq) error {
		close(entered)
		select {
		case <-release:
			return runtime.Debuglet.StartServers(ctx, req)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.initializeDebuglet(ctx, spec, runtime) }()
	if !operationAwait(t, entered, "listener setup") {
		return
	}
	vantage := &pb.VantagePointReport{Listeners: []string{"tcp"}}
	e.probeConnectivity(t.Context(), spec.Binding, vantage)()
	if vantage.Connectivity != nil || !e.connectivityNext.IsZero() {
		t.Fatal("skipped proof replaced the prior observation or delayed the next sample")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(operationTestBound):
		t.Fatal("listener setup did not finish")
	}
}

func TestConnectivityHeartbeatLookupBounded(t *testing.T) {
	e, _, spec := listenerSetupFixture(t, config.PolicyConfig{})
	entered := make(chan context.Context, 1)
	lookupDone, loopDone := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	e.clientFor = func(ctx context.Context, _ controlsession.Binding) (pb.DispatcherServiceClient, error) {
		entered <- ctx
		<-ctx.Done()
		cancel() // Stop before the next queued heartbeat tick can enter again.
		close(lookupDone)
		return nil, ctx.Err()
	}
	go func() { e.startHeartbeatLoop(ctx, spec.Binding); close(loopDone) }()
	t.Cleanup(func() { cancel(); operationJoinCleanup(t, loopDone, "heartbeat lookup") })
	select {
	case callCtx := <-entered:
		deadline, ok := callCtx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("dispatcher lookup is outside the heartbeat call budget")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat did not reach dispatcher lookup")
	}
	select {
	case <-lookupDone:
	case <-time.After(3 * time.Second):
		t.Fatal("dispatcher lookup outlasted its heartbeat deadline")
	}
	cancel()
	if !operationAwait(t, loopDone, "heartbeat cleanup") {
		return
	}
	listener, port, _, err := e.portManager.ListenTCP(nil)
	if err != nil {
		t.Fatal("failed heartbeat lookup retained its proof listener:", err)
	}
	listener.Close()
	e.portManager.Release(port)
}
