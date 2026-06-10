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
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"debuglet/internal/executor/bpf"
	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/debuglet/wasm"
	"debuglet/internal/executor/platform"
	"debuglet/pkg/tagger"
	"debuglet/pkg/tesla"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/wasmerio/wasmer-go/wasmer"
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
	logger *zap.SugaredLogger
	engine *wasmer.Engine
	store  *wasmer.Store

	wasiEnv        *wasmer.WasiEnvironment
	wasmerInstance *wasmer.Instance

	scionServer pan.ListenConn
	udpServer   net.PacketConn
	tcpServer   *net.TCPListener
	ipServer    net.Listener

	pktTagger tagger.TaggerInterface

	// addresses is the list of peer addresses made available to the WASM module.
	addresses []string

	started bool
	hostEnv *wasm.HostEnvironment

	createdAt time.Time
	mu        sync.Mutex

	// stdoutCh buffers WASI stdout/stderr chunks while the debuglet runs.
	stdoutCh chan []byte
	closed   bool
}

// NewDebuglet creates a ready-to-initialise Debuglet backed by a new wasmer
// Engine and Store.
func New(logger *zap.Logger, debugletID string, schedule *tesla.KeySchedule) *Debuglet {
	eng := wasmer.NewEngine()

	var pktTagger tagger.TaggerInterface
	if runtime.GOOS == "linux" {
		iface := os.Getenv("DEBUGLET_IFACE")
		if iface == "" {
			iface = "eth0"
		}
		// Try to initialize eBPF tagger.
		if bt, err := bpf.NewBPFTagger(iface, schedule, []byte(debugletID)); err == nil {
			pktTagger = bt
		} else {
			fmt.Printf("bpf: failed to initialize BPF tagger on %s: %v. Falling back to Go tagger.\n", iface, err)
			// Fallback to lo if eth0 failed and we are local
			if iface == "eth0" {
				if bt, err := bpf.NewBPFTagger("lo", schedule, []byte(debugletID)); err == nil {
					pktTagger = bt
					fmt.Printf("bpf: successfully fell back to lo\n")
				}
			}
		}

		if pktTagger == nil {
			logger.Warn("Failed to initialize BPF tagger, falling back to pure-Go")
			pktTagger = tagger.New(schedule, []byte(debugletID))
		}
	} else {
		pktTagger = tagger.New(schedule, []byte(debugletID))
	}

	return &Debuglet{
		logger:    logger.Sugar(),
		engine:    eng,
		store:     wasmer.NewStore(eng),
		createdAt: time.Now(),
		stdoutCh:  make(chan []byte, 1024),
		pktTagger: pktTagger,
		hostEnv:   wasm.NewHostEnvironment(debugletID),
	}
}

// StdoutChan returns the channel on which WASI stdout/stderr bytes are
// published while the debuglet executes.
func (d *Debuglet) StdoutChan() <-chan []byte {
	return d.stdoutCh
}

// Init starts the network servers and compiles and instantiates the WASM
// module. It must be called exactly once before Run.
func (d *Debuglet) Init(ctx context.Context, wasmBytes []byte, addresses []string) error {
	if err := d.startServers(ctx); err != nil {
		d.logger.Warnw("failed to start up server(s)", "err", err)
	}
	if err := d.createWASMInstance(wasmBytes); err != nil {
		return err
	}
	d.addresses = addresses
	return nil
}

// GetSCIONAddr returns the local SCION address of the server listener started
// during Init.
func (d *Debuglet) GetSCIONAddr() string {
	if d.scionServer == nil {
		return ""
	}
	return d.scionServer.LocalAddr().String()
}

// startServers starts the network listeners required by this debuglet instance.
// Currently only the SCION/UDP listener is active; TCP and plain UDP are
// reserved for future use.
func (d *Debuglet) startServers(ctx context.Context) error {
	d.logger.Debugw("startServers: starting")

	// -- Placeholder for future UDP server --
	// udpServer, err := net.ListenPacket("udp", ":0")

	// -- Placeholder for future TCP server --
	// addr, err := net.ResolveTCPAddr("tcp", ":0")
	// tcpServer, err := net.ListenTCP("tcp", addr)

	// -- Placeholder for future IP server --
	// ipAddr, err := net.ResolveIPAddr("ip", ":0")
	// ipServer, err := net.ListenIP("ip", ipAddr)

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

	d.logger.Debug("startServers: starting scion UDP listener")
	scionServer, err := pan.ListenUDP(ctx, listen.Get(), nil)
	if err != nil {
		return fmt.Errorf("startServers: failed to start SCION UDP listener: %w", err)
	}
	d.scionServer = scionServer

	d.logger.Debugw("startServers: started", "SCION", scionServer.LocalAddr())
	return nil
}

// createWASMInstance compiles the given WASM bytecode and instantiates a
// wasmer Instance with all host functions registered.
func (d *Debuglet) createWASMInstance(wasmBytes []byte) error {
	module, err := wasmer.NewModule(d.store, wasmBytes)
	if err != nil {
		d.logger.Warnw("createWASMInstance: module compile failed", "err", err)
		return fmt.Errorf("createWASMInstance: bytecode is probably malformed: %w", err)
	}

	d.logger.Debug("producing new debuglet WasiEnvironment")
	wasiEnv, err := wasmer.NewWasiStateBuilder("debuglet").
		CaptureStdout().
		CaptureStderr().
		Finalize()
	if err != nil {
		return fmt.Errorf("createWASMInstance: WASI finalize failed: %w", err)
	}
	d.wasiEnv = wasiEnv

	d.logger.Debug("generating new debuglet import object")
	importObject, err := d.wasiEnv.GenerateImportObject(d.store, module)
	if err != nil {
		return fmt.Errorf("createWASMInstance: generate import object failed: %w", err)
	}

	// Per-session state shared across host function calls.
	scionConns := socket.NewSCIONConnRegistry(scionConnCapacity)
	socketRegistry := &socket.SocketRegistry{}
	var lastReceived net.Addr

	d.logger.Debug("registering host functions for WASM")
	d.registerHostFunctions(importObject, scionConns, socketRegistry, &lastReceived)

	instance, err := wasmer.NewInstance(module, importObject)
	if err != nil {
		d.logger.Warnw("createWASMInstance: instantiation failed", "err", err)
		return fmt.Errorf("createWASMInstance: failed to instantiate: %w", err)
	}
	d.wasmerInstance = instance
	return nil
}

// registerHostFunctions populates the importObject with all host functions
// that WASM modules may call. WASM-visible key strings are kept stable; only
// the Go-side implementation names have changed.
func (d *Debuglet) registerHostFunctions(importObject *wasmer.ImportObject, scionConns *socket.SCIONConnRegistry, sockets *socket.SocketRegistry, lastReceived *net.Addr) {
	i32 := wasmer.I32
	i64 := wasmer.I64
	in := wasmer.NewValueTypes
	out := wasmer.NewValueTypes

	importObject.Register("env", map[string]wasmer.IntoExtern{
		// ---- Context / timing ----
		"wait_start": d.hostEnv.WrapHostFn(d.store, in(), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				d.markStarted()
				return wasm.HostWaitStart(env, args)
			},
		),

		"get_timestamp": d.hostEnv.WrapHostFn(d.store, in(), out(i64),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostGetTimestamp(env, args)
			},
		),

		"wait_until": d.hostEnv.WrapHostFn(d.store, in(i64), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostWaitUntil(env, args)
			},
		),

		"sleep": d.hostEnv.WrapHostFn(d.store, in(i64), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostSleep(env, args)
			},
		),

		// ---- TCP socket API ----
		"connect_tcp": d.hostEnv.WrapHostFn(d.store, in(i32), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostConnect(socket.SocketTypeTCP, env, args, d.addresses, d.logger, sockets, nil, d.pktTagger)
			},
		),

		"connect_tls": d.hostEnv.WrapHostFn(d.store, in(i32), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostConnect(socket.SocketTypeTLS, env, args, d.addresses, d.logger, sockets, nil, d.pktTagger)
			},
		),

		"accept_tcp": d.hostEnv.WrapHostFn(d.store, in(), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostAcceptTCP(env, args, d.tcpServer, d.logger, sockets)
			},
		),

		"receive_tcp_data": d.hostEnv.WrapHostFn(d.store, in(i32, i32, i32), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostReceiveData(env, args, d.logger, sockets, d.wasmerInstance)
			},
		),

		"send_tcp_data": d.hostEnv.WrapHostFn(d.store, in(i32, i32, i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostSendData(env, args, d.logger, sockets, d.wasmerInstance)
			},
		),

		"close_tcp": d.hostEnv.WrapHostFn(d.store, in(i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostClose(env, args, d.logger, sockets)
			},
		),

		// ---- IP socket API ----
		"connect_icmp4": d.hostEnv.WrapHostFn(d.store, in(i32), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostConnect(socket.SocketTypeICMP4, env, args, d.addresses, d.logger, sockets, nil, d.pktTagger)
			},
		),

		"accept_icmp4": d.hostEnv.WrapHostFn(d.store, in(), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostAcceptIP(env, args, d.ipServer, d.logger, sockets)
			},
		),

		"receive_icmp4_data": d.hostEnv.WrapHostFn(d.store, in(i32, i32, i32), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostReceiveData(env, args, d.logger, sockets, d.wasmerInstance)
			},
		),

		"send_icmp4_data": d.hostEnv.WrapHostFn(d.store, in(i32, i32, i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostSendData(env, args, d.logger, sockets, d.wasmerInstance)
			},
		),

		"close_icmp4": d.hostEnv.WrapHostFn(d.store, in(i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostClose(env, args, d.logger, sockets)
			},
		),

		// ---- SCION-UDP API ----
		"send_scion_udp_packet": d.hostEnv.WrapHostFn(d.store, in(i32, i32), out(i64),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostSendSCIONUDPPacket(env, args, scionConns, d.addresses, d.logger, d.wasmerInstance, d.pktTagger)
			},
		),

		"receive_scion_server_udp_packet": d.hostEnv.WrapHostFn(d.store, in(i32), out(i32, i64),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				d.markStarted()
				return wasm.HostReceiveSCIONServerUDPPacket(env, args, lastReceived, d.logger, d.wasmerInstance, &d.scionServer, d.pktTagger)
			},
		),

		"scion_available_paths": d.hostEnv.WrapHostFn(d.store, in(i32), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostSCIONAvailablePaths(env, args, scionConns, d.addresses, d.logger, d.pktTagger)
			},
		),

		"scion_path_length": d.hostEnv.WrapHostFn(d.store, in(i32, i32), out(i32),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostSCIONPathLength(env, args, scionConns, d.addresses, d.logger, d.pktTagger)
			},
		),

		"scion_get_interface_details": d.hostEnv.WrapHostFn(d.store, in(i32, i32, i32), out(i64, i64),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostSCIONGetInterfaceDetails(env, args, scionConns, d.addresses, d.logger, d.pktTagger)
			},
		),

		"scion_select_path": d.hostEnv.WrapHostFn(d.store, in(i32, i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostSCIONSelectPath(env, args, scionConns, d.addresses, d.logger, d.pktTagger)
			},
		),

		// ---- Debug write API ----
		"write": d.hostEnv.WrapHostFn(d.store, in(i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostWriteString(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_noeol": d.hostEnv.WrapHostFn(d.store, in(i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostWriteStringNoEOL(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_i32": d.hostEnv.WrapHostFn(d.store, in(i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostWriteI32(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_i64": d.hostEnv.WrapHostFn(d.store, in(i64), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostWriteI64(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_i32x": d.hostEnv.WrapHostFn(d.store, in(i32), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostWriteI32Hex(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_i64x": d.hostEnv.WrapHostFn(d.store, in(i64), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostWriteI64Hex(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_delta_timestamp": d.hostEnv.WrapHostFn(d.store, in(i64), out(),
			func(env *wasm.HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error) {
				return wasm.HostWriteDeltaTimestamp(env, args, d.logger)
			},
		),
	})
}

// Close shuts down all network listeners and the wasmer instance.
func (d *Debuglet) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.scionServer != nil {
		_ = d.scionServer.Close()
	}
	if d.udpServer != nil {
		_ = d.udpServer.Close()
	}
	if d.tcpServer != nil {
		_ = d.tcpServer.Close()
	}
	if d.ipServer != nil {
		_ = d.ipServer.Close()
	}
	if d.wasmerInstance != nil {
		inst := d.wasmerInstance
		d.wasmerInstance = nil // nil first so flushWASIOutput sees it immediately
		inst.Close()
	}
	if d.pktTagger != nil {
		d.pktTagger.Close()
	}

	if !d.closed {
		close(d.stdoutCh)
		d.closed = true
	}
}

// Run executes the debuglet's "run_debuglet" WASM export, streams stdout/stderr
// back through StdoutChan, and returns the result bytes written to the WASM
// result buffer.
func (d *Debuglet) Run(ctx context.Context) ([]byte, error) {
	instance := d.wasmerInstance

	// Optional initialization
	initFunc, err := instance.Exports.GetFunction("_initialize")
	if err == nil {
		if _, initErr := initFunc(); initErr != nil {
			d.logger.Warnw("Run: initialization error", "err", initErr)
			return nil, fmt.Errorf("failed to initialize Go runtime: %w", initErr)
		}
	}

	runFunc, err := instance.Exports.GetFunction("run_debuglet")
	if err != nil {
		d.logger.Warnw("Run: 'run_debuglet' not exported", "err", err)
		return nil, fmt.Errorf("run_debuglet is not correctly exported: %w", err)
	}

	d.hostEnv.SetContext(ctx)

	done := make(chan error, 1)
	var result []byte

	go func() {
		defer func() {
			if r := recover(); r != nil {
				d.logger.Errorf("Run: recovered from panic: %v", r)
				done <- fmt.Errorf("debuglet panicked: %v", r)
			}
		}()

		d.logger.Debug("starting execution")
		if _, runErr := runFunc(); runErr != nil {
			d.logger.Warnw("Run: execution error", "err", runErr)
			done <- fmt.Errorf("error running debuglet: %w", runErr)
			return
		}

		resIdx, err := wasm.ExtractResIdx(instance)
		if err != nil {
			done <- fmt.Errorf("failed to retrieve result index: %w", err)
			return
		}

		resultSize := int32(binary.LittleEndian.Uint32(resIdx))
		result, err = wasm.GetResult(instance, resultSize)
		if err != nil {
			d.logger.Warnw("Run: failed to retrieve result", "err", err)
			done <- fmt.Errorf("failed to retrieve result: %w", err)
			return
		}
		done <- nil
	}()

	ticker := time.NewTicker(stdoutPollInterval)
	defer ticker.Stop()

	var retErr error
StreamLoop:
	for {
		select {
		case <-ctx.Done():
			retErr = ctx.Err()
			break StreamLoop
		case err := <-done:
			d.flushWASIOutput()
			retErr = err
			break StreamLoop
		case <-ticker.C:
			// Flush available stdout/stderr — do NOT break the loop here.
			d.flushWASIOutput()
		}
	}
	return result, retErr
}

// markStarted records that the debuglet has begun active execution.
func (d *Debuglet) markStarted() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.started {
		d.started = true
	}
}

// flushWASIOutput drains the WASI stdout buffer and forwards it to stdoutCh.
// ReadStdout is called while the mutex is held so that a concurrent Close()
// cannot free the underlying C memory between the nil-check and the read.
func (d *Debuglet) flushWASIOutput() {
	d.mu.Lock()
	if d.closed || d.wasmerInstance == nil || d.wasiEnv == nil {
		d.mu.Unlock()
		return
	}
	buf := d.wasiEnv.ReadStdout()
	d.mu.Unlock()
	if len(buf) > 0 {
		d.stdoutCh <- buf
	}
}
