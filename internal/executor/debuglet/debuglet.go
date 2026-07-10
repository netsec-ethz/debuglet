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

package debuglet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"runtime"
	"sync"
	"time"

	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/debuglet/wasm"
	"debuglet/internal/executor/platform"
	"debuglet/internal/executor/ratelimit/app"
	ratebpf "debuglet/internal/executor/ratelimit/ebpf"
	"debuglet/internal/executor/scheduler"
	"debuglet/internal/executor/tagger"
	"debuglet/internal/executor/tagger/ebpf"
	"debuglet/internal/executor/tagger/tesla"

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
	id     string
	policy scheduler.Policy

	// wazero runtime state
	runtime  wazero.Runtime
	compiled wazero.CompiledModule

	createdAt time.Time
	mu        sync.Mutex

	env *wasm.WasmEnv
}

// New creates a ready-to-initialise Debuglet backed by a wazero Runtime.
func New(logger *zap.Logger, debugletID string, policy scheduler.Policy, schedule *tesla.KeySchedule, limiter *app.Limiter, pc *ratebpf.PacketCount) *Debuglet {
	// setup tagging
	var pktTagger tagger.TaggerInterface
	if runtime.GOOS == "linux" {
		iface, err := ratebpf.GetDefaultInterface()
		if err != nil {
			logger.Warn("Failed to get default network interface for eBPF tagging; falling back to pure-Go tagger", zap.Error(err))
		} else if bt, err := ebpf.NewBPFTagger(iface, schedule, []byte(debugletID)); err == nil {
			// Try to initialize eBPF tagger.
			pktTagger = bt
		} else {
			logger.Warn("Failed to initialize BPF tagger, falling back to pure-Go")
			pktTagger = tagger.New(schedule, []byte(debugletID))
		}

		if pktTagger == nil {
		}
	} else {
		pktTagger = tagger.New(schedule, []byte(debugletID))
	}

	env := wasm.WasmEnv{
		DebugletID:  debugletID,
		Policy:      policy,
		Limiter:     limiter,
		PacketCount: pc,
		Logger:      logger.Sugar(),
		TlsCfg:      &tls.Config{},
		Tagger:      pktTagger,

		Registry:  &socket.SocketRegistry{},
		ScionConn: socket.NewSCIONConnRegistry(scionConnCapacity),
	}

	return &Debuglet{
		id:        debugletID,
		policy:    policy,
		createdAt: time.Now(),
		env:       &env,
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

func (d *Debuglet) StartServers(ctx context.Context) error {
	return d.startServers(ctx)
}

// GetSCIONAddr returns the local SCION address of the server listener started
// during Init.
func (d *Debuglet) GetSCIONAddr() string {
	if d.env.ScionServer == nil {
		return ""
	}
	return d.env.ScionServer.LocalAddr().String()
}

func (d *Debuglet) ID() string                       { return d.id }
func (d *Debuglet) Registry() *socket.SocketRegistry { return d.env.Registry }

// startServers starts the network listeners required by this debuglet instance.
// Currently only the SCION/UDP listener is active; TCP and plain UDP are
// reserved for future use.
func (d *Debuglet) startServers(ctx context.Context) error {
	d.env.Logger.Debugw("startServers: starting")

	// -- Placeholder for future UDP server --
	// udpServer, err := net.ListenPacket("udp", ":0")
	// d.env.UdpServer = udpServer

	// -- Placeholder for future TCP server --
	// addr, err := net.ResolveTCPAddr("tcp", ":0")
	// tcpServer, err := net.ListenTCP("tcp", addr)
	// d.env.TcpServer = tcpServer

	// -- Placeholder for future IP server --
	// ipAddr, err := net.ResolveIPAddr("ip", ":0")
	// ipServer, err := net.ListenIP("ip", ipAddr)
	// d.env.IpServer = ipServer

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
	d.env.ScionServer = scionServer

	d.env.Logger.Debugw("startServers: started", "SCION", scionServer.LocalAddr())
	return nil
}

// createWASMInstance compiles the given WASM bytecode and instantiates a
// wazero module with WASI and all host functions registered.
func (d *Debuglet) createWASMInstance(ctx context.Context, wasmBytes []byte) error {
	d.runtime = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())

	compiled, err := d.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		d.env.Logger.Warnw("createWASMInstance: module compile failed", "err", err)
		return fmt.Errorf("createWASMInstance: bytecode is probably malformed: %w", err)
	}
	d.compiled = compiled

	d.env.Logger.Debug("instantiating WASI (wasi_snapshot_preview1)")
	if _, err := wasi.Instantiate(ctx, d.runtime); err != nil {
		return fmt.Errorf("createWASMInstance: WASI instantiation failed: %w", err)
	}

	d.env.Logger.Debug("building host 'env' module")
	hmb := d.runtime.NewHostModuleBuilder("env")
	hmb = d.registerHostFunctions(hmb)
	if _, err := hmb.Instantiate(ctx); err != nil {
		return fmt.Errorf("createWASMInstance: host module instantiation failed: %w", err)
	}

	return nil
}

// registerHostFunctions populates the host module builder with all host functions
// that WASM modules may call. WASM-visible key strings are kept stable; only
// the Go-side implementation names have changed.
func (d *Debuglet) registerHostFunctions(hmb wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	// ---- Generic socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(d.env, socket.SocketTypeTCP)).Export("connect_tcp")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(d.env, socket.SocketTypeTLS)).Export("connect_tls")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveData(d.env)).Export("receive_tcp_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendData(d.env)).Export("send_tcp_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostClose(d.env)).Export("close_tcp")

	// ---- TCP socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostAcceptTCP(d.env)).Export("accept_tcp")

	// ---- IP socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(d.env, socket.SocketTypeICMP4)).Export("connect_icmp4")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostAcceptIP(d.env)).Export("accept_icmp4")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveData(d.env)).Export("receive_icmp4_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendData(d.env)).Export("send_icmp4_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostClose(d.env)).Export("close_icmp4")

	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostDrain(d.env)).Export("drain_connection")

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

// Close cleans up all the resources used by the debuglet
func (d *Debuglet) Close(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.env.Limiter.RemoveDebuglet(d.id)
	d.env.Close()

	if d.runtime != nil {
		d.runtime.Close(ctx)
	}
}

type chanWriter struct {
	ch chan<- []byte
}

func (w *chanWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	temp := make([]byte, len(p))
	copy(temp, p)
	w.ch <- temp
	return len(p), nil
}

// Run executes the debuglet's "run_debuglet" WASM export, streams stdout/stderr
// back through outputCh, and returns any execution error.
// The outputCh channel is closed when the debuglet finishes execution.
func (d *Debuglet) Run(ctx context.Context, outputCh chan<- []byte, args []string) error {
	writer := &chanWriter{ch: outputCh}
	defer close(outputCh)

	config := wazero.NewModuleConfig().
		WithStdout(writer).
		WithStderr(writer).
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep().
		WithRandSource(rand.Reader).
		WithArgs(args...)

	// start the wasm
	mod, err := d.runtime.InstantiateModule(ctx, d.compiled, config)
	if err != nil {
		return fmt.Errorf("failed to instantiate module: %w", err)
	}
	mod.Close(ctx)

	return nil

}
