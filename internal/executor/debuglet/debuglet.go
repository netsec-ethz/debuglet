// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package debuglet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
	"github.com/netsec-ethz/debuglet/internal/executor/platform"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"

	"github.com/google/uuid"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/tetratelabs/wazero"
	wasi "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"go.uber.org/zap"
)

const (
	// stdoutPollInterval controls how often WASI stdout/stderr is flushed to
	// the StdoutChan during a running debuglet.
	stdoutPollInterval = 100 * time.Millisecond

	// defaultExecTimeout is the maximum allowed runtime for a single debuglet.
	defaultExecTimeout = 5 * time.Minute

	// scionConnCapacity is the default pre-allocated capacity for the SCION
	// connection registry.
	scionConnCapacity = 16
)

// Debuglet is the engine that loads, initialises, and runs a single WASM
// debuglet module. One Debuglet instance corresponds to one session.
type Debuglet struct {
	id     uuid.UUID
	policy scheduler.Policy

	// wazero runtime state
	runtime  wazero.Runtime
	compiled wazero.CompiledModule

	createdAt    time.Time
	mu           sync.Mutex
	closed       bool
	initialized  bool
	closeOnce    sync.Once
	closeErr     error
	lateCloseErr error

	env *wasm.WasmEnv

	transactionID string
}

// New creates a ready-to-initialise Debuglet backed by a wazero Runtime.
// operator is the executor's network policy; together with the run's declared
// destinations it decides every transport the guest can use.
func New(logger *zap.Logger, debugletID uuid.UUID, transactionID string, policy scheduler.Policy, operator netpolicy.Operator, schedule *tesla.KeySchedule, limiter *app.Limiter, pc ratelimit.PacketCount, iface *net.Interface, portManager *socket.PortManager) *Debuglet {
	return newWithBPFTagger(logger, debugletID, transactionID, policy, operator, schedule, limiter, pc, iface, portManager, ebpf.NewBPFTagger)
}

// The constructor dependency is per call; production and fixtures execute the
// same fallback/environment path without a mutable package-wide factory.
func newWithBPFTagger(logger *zap.Logger, debugletID uuid.UUID, transactionID string, policy scheduler.Policy, operator netpolicy.Operator, schedule *tesla.KeySchedule, limiter *app.Limiter, pc ratelimit.PacketCount, iface *net.Interface, portManager *socket.PortManager, newBPF func(*net.Interface, *tesla.KeySchedule, []byte) (*ebpf.BPFTagger, error)) *Debuglet {
	// setup tagging
	var pktTagger tagger.TaggerInterface
	var constructorCleanup error
	if iface != nil && runtime.GOOS == "linux" {
		if bt, err := newBPF(iface, schedule, []byte(debugletID.String())); err == nil {
			logger.Info("Using eBPF packet tagger", zap.String("interface", iface.Name))
			pktTagger = bt
		} else {
			constructorCleanup = ebpf.CleanupError(err)
			logger.Warn("Failed to initialize BPF tagger, falling back to pure-Go", zap.Error(err))
		}
	}

	if pktTagger == nil {
		// The pure-Go tagger only rewrites buffers handed to it explicitly;
		// the socket data path relies on SO_MARK + TC egress, so nothing is
		// tagged on this path and packet attribution is unavailable.
		logger.Warn("No eBPF tagger available: outgoing packets will NOT carry attribution tags",
			zap.Bool("interface_configured", iface != nil), zap.String("goos", runtime.GOOS))
		pktTagger = tagger.New(schedule, []byte(debugletID.String()))
	}

	env := wasm.WasmEnv{
		DebugletID: debugletID,
		Policy:     policy,
		Net: netpolicy.New(operator, netpolicy.Run{
			Addresses:   policy.Addresses,
			RequireICMP: policy.RequireICMP,
			ListenTCP:   policy.ListenTCP,
			ListenUDP:   policy.ListenUDP,
			ListenSCION: policy.ListenSCION,
		}),
		Limiter:     limiter,
		Accountant:  ratelimit.NewAccountant(limiter, debugletID),
		PacketCount: pc,
		Logger:      logger.Sugar(),
		TlsCfg:      &tls.Config{},
		Tagger:      pktTagger,

		Registry:  &socket.SocketRegistry{},
		ScionConn: socket.NewSCIONConnRegistry(scionConnCapacity),

		PortManager: portManager,
	}
	env.RecordCleanupError(constructorCleanup)

	return &Debuglet{
		id:            debugletID,
		policy:        policy,
		createdAt:     time.Now(),
		env:           &env,
		transactionID: transactionID,
	}
}

// InitRuntime starts the network servers and compiles and instantiates the WASM
// module. It must be called exactly once before Run.
func (d *Debuglet) InitRuntime(ctx context.Context, wasmBytes []byte) error {
	if err := d.createWASMInstance(ctx, wasmBytes); err != nil {
		return err
	}
	return nil
}

// GetSCIONAddr returns the local SCION address of the server listener started
// during Init.
func (d *Debuglet) GetSCIONAddr() string { return d.env.SCIONAddr() }

func (d *Debuglet) ID() uuid.UUID                    { return d.id }
func (d *Debuglet) Registry() *socket.SocketRegistry { return d.env.Registry }

type StartServersReq struct {
	UDP   bool
	TCP   bool
	SCION bool
}

// startServers starts the network listeners required by this debuglet instance.
// Currently only the SCION/UDP listener is active; TCP and plain UDP are
// reserved for future use.
func (d *Debuglet) StartServers(ctx context.Context, req StartServersReq) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if req.TCP {
		d.env.Logger.Debug("startServers: starting TCP listener")
		if err := d.env.Net.AvailableListener(netpolicy.TCP); err != nil {
			return fmt.Errorf("startServers: TCP listener: %w", err)
		}
		if !d.env.PortManager.Enabled() {
			return fmt.Errorf("startServers: TCP listener requested but not enabled (public_host/public_ports not configured)")
		}
		lis, port, addr, err := d.env.PortManager.ListenTCP()
		if err != nil {
			return fmt.Errorf("startServers: failed to start TCP listener: %w", err)
		}
		if err := d.env.InstallTCP(lis, port, addr); err != nil {
			return err
		}
	}

	if req.UDP {
		d.env.Logger.Debug("startServers: starting UDP listener")
		if err := d.env.Net.AvailableListener(netpolicy.UDP); err != nil {
			return fmt.Errorf("startServers: UDP listener: %w", err)
		}
		if !d.env.PortManager.Enabled() {
			return fmt.Errorf("startServers: UDP listener requested but not enabled (public_host/public_ports not configured)")
		}
		conn, port, addr, err := d.env.PortManager.ListenUDP()
		if err != nil {
			return fmt.Errorf("startServers: failed to start UDP listener: %w", err)
		}
		if err := d.env.InstallUDP(conn, port, addr); err != nil {
			return err
		}
	}

	if req.SCION {
		d.env.Logger.Debug("startServers: starting SCION listener")
		if err := d.env.Net.AvailableListener(netpolicy.SCION); err != nil {
			return fmt.Errorf("startServers: SCION listener: %w", err)
		}
		scionHost, err := platform.GetScionAddr(ctx)
		if err != nil {
			return fmt.Errorf("startServers: failed to get SCION address: %w", err)
		}
		scionAddr, err := pan.ParseUDPAddr(scionHost)
		if err != nil {
			return fmt.Errorf("startServers: failed to parse SCION address: %w", err)
		}

		var listen pan.IPPortValue
		if err = listen.Set(scionAddr.IP.String() + ":0"); err != nil {
			return fmt.Errorf("startServers: failed to set SCION listen addr: %w", err)
		}

		d.env.Logger.Debug("startServers: starting scion UDP listener")
		scionServer, err := pan.ListenUDP(ctx, listen.Get(), nil)
		if err != nil {
			return fmt.Errorf("startServers: failed to start SCION UDP listener: %w", err)
		}
		if err := d.env.InstallSCION(scionServer); err != nil {
			return err
		}

		d.env.Logger.Debugw("startServers: started", "SCION", scionServer.LocalAddr())
	}

	return nil
}

// createWASMInstance compiles the given WASM bytecode and instantiates a
// wazero module with WASI and all host functions registered.
func (d *Debuglet) createWASMInstance(ctx context.Context, wasmBytes []byte) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	// Publish the runtime before compilation, so cancellation has a stable
	// resource to close. Compile itself is not forcibly preemptible.
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return net.ErrClosed
	}
	if d.initialized {
		d.mu.Unlock()
		return errors.New("runtime already initialized")
	}
	d.initialized = true
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithCloseOnContextDone(true))
	d.runtime = rt
	d.mu.Unlock()
	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("createWASMInstance: compile: %w", err)
	}
	if err := d.publishCompiled(ctx, compiled); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if _, err := wasi.Instantiate(ctx, rt); err != nil {
		return fmt.Errorf("createWASMInstance: WASI instantiation: %w", err)
	}
	if _, err := d.registerHostFunctions(rt.NewHostModuleBuilder("env")).Instantiate(ctx); err != nil {
		return fmt.Errorf("createWASMInstance: host module instantiation: %w", err)
	}
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return context.Cause(ctx)
}

// publishCompiled consumes compilation's result even if cancellation closed
// the runtime while the compiler was still running.
func (d *Debuglet) publishCompiled(ctx context.Context, compiled wazero.CompiledModule) error {
	d.mu.Lock()
	closed := d.closed
	if !closed {
		d.compiled = compiled
	}
	d.mu.Unlock()
	if !closed {
		return nil
	}
	err := compiled.Close(context.WithoutCancel(ctx))
	d.mu.Lock()
	d.lateCloseErr = errors.Join(d.lateCloseErr, err)
	d.mu.Unlock()
	return errors.Join(net.ErrClosed, err)
}

// registerHostFunctions populates the host module builder with all host functions
// that WASM modules may call. WASM-visible key strings are kept stable; only
// the Go-side implementation names have changed.
func (d *Debuglet) registerHostFunctions(hmb wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(d.env, socket.SocketTypeTLS)).Export("connect_tls")

	// ---- TCP socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(d.env, socket.SocketTypeTCP)).Export("connect_tcp")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveData(d.env)).Export("receive_tcp_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendData(d.env)).Export("send_tcp_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostClose(d.env)).Export("close_tcp")

	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostAcceptTCP(d.env)).Export("accept_tcp")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostGetTCPAddr(d.env)).Export("get_tcp_addr")

	// ---- UDP socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(d.env, socket.SocketTypeUDP)).Export("connect_udp")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveData(d.env)).Export("receive_udp_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendData(d.env)).Export("send_udp_data")

	// ---- UDP listener API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveUDPFrom(d.env)).Export("receive_udp_from")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostGetUDPAddr(d.env)).Export("get_udp_addr")

	// ---- ICMP socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(d.env, socket.SocketTypeICMP4)).Export("connect_icmp4")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveData(d.env)).Export("receive_icmp4_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendData(d.env)).Export("send_icmp4_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostClose(d.env)).Export("close_icmp4")

	// ---- Connection Util API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostDrain(d.env)).Export("drain_connection")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostGetRemoteAddr(d.env)).Export("get_remote_addr")

	// ---- SCION-UDP API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendSCIONUDPPacket(d.env)).Export("send_scion_udp_packet")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveSCIONServerUDPPacket(d.env)).Export("receive_scion_server_udp_packet")
	// HACK: HostAnswerSCIONUDPPacket expects a list of addresses. This has been removed for the time being as the function is not being worked on or used
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostAnswerSCIONUDPPacket(d.env, []string{})).Export("answer_scion_udp_packet")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSCIONAvailablePaths(d.env)).Export("scion_available_paths")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSCIONPathLength(d.env)).Export("scion_path_length")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSCIONGetInterfaceDetails(d.env)).Export("scion_get_interface_details")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSCIONSelectPath(d.env)).Export("scion_select_path")

	return hmb
}

// Close terminates owned I/O and runtime resources exactly once. It does not
// wait for Run or its caller's watcher: the executor joins those separately.
// The context reaches wazero; it cannot force an arbitrary socket Close to end.
func (d *Debuglet) Close(ctx context.Context) error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		rt, compiled := d.runtime, d.compiled
		d.mu.Unlock()
		if d.env != nil {
			_ = d.env.Close()
			if d.env.Limiter != nil {
				d.env.Limiter.RemoveDebuglet(d.id)
			}
		}
		if rt != nil {
			d.closeErr = errors.Join(d.closeErr, rt.Close(ctx))
		}
		if compiled != nil {
			d.closeErr = errors.Join(d.closeErr, compiled.Close(ctx))
		}
	})
	d.mu.Lock()
	lateErr := d.lateCloseErr
	d.mu.Unlock()
	var envErr error
	if d.env != nil {
		envErr = d.env.Close()
	}
	return errors.Join(d.closeErr, envErr, lateErr)
}

type chanWriter struct {
	ctx context.Context
	ch  chan<- []byte
}

func (w *chanWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, context.Cause(w.ctx)
	}
	if len(p) == 0 {
		return 0, nil
	}
	temp := append([]byte(nil), p...)
	select {
	case <-w.ctx.Done():
		return 0, context.Cause(w.ctx)
	case w.ch <- temp:
		return len(p), nil
	}
}

// Run executes the debuglet's "_start" WASM export, streams stdout/stderr
// back through outputCh, and returns any execution error.
// The outputCh channel is closed when the debuglet finishes execution.
func (d *Debuglet) Run(ctx context.Context, outputCh chan<- []byte, args []string) error {
	writer := &chanWriter{ctx: ctx, ch: outputCh}
	defer close(outputCh)

	d.mu.Lock()
	rt, compiled, closed := d.runtime, d.compiled, d.closed
	d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if closed {
		return net.ErrClosed
	}
	if rt == nil || compiled == nil {
		return errors.New("runtime is not initialized")
	}
	config := wazero.NewModuleConfig().
		WithStdout(writer).
		WithStderr(writer).
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep().
		WithRandSource(rand.Reader).
		WithArgs(args...)

	start := time.Now()

	// start the wasm
	mod, err := rt.InstantiateModule(ctx, compiled, config)
	d.env.Logger.Debugw("debuglet execution finished", "duration", time.Since(start), "has_error", err != nil)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("debuglet execution canceled: %w", context.Cause(ctx))
		}
		return fmt.Errorf("failed to instantiate module: %w", err)
	}
	closeErr := mod.Close(ctx)
	d.mu.Lock()
	d.lateCloseErr = errors.Join(d.lateCloseErr, closeErr)
	d.mu.Unlock()
	// WASI may translate a canceled stdout Write to errno and return normally.
	// A successful Instantiate is not proof of a successful canceled execution.
	if ctx.Err() != nil {
		return errors.Join(context.Cause(ctx), closeErr)
	}
	return closeErr

}
