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

package engine

import (
	"context"
	"debuglet/internal/platform"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

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

// hostFunction is the function signature expected by wasmer's import mechanism.
type hostFunction func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error)

// HostEnvironment carries the execution context for the current debuglet
// session. It is passed by value to each host function.
type HostEnvironment struct {
	ctx context.Context
}

// checkContextExpired returns a descriptive error if the HostEnvironment's
// context has been cancelled or has exceeded its deadline.
func checkContextExpired(env HostEnvironment) error {
	select {
	case <-env.ctx.Done():
	default:
		return nil
	}
	switch err := env.ctx.Err(); err {
	case context.DeadlineExceeded:
		return fmt.Errorf("debuglet exceeded maximum allowed runtime")
	default:
		return fmt.Errorf("debuglet context cancelled: %w", err)
	}
}

// Debuglet is the engine that loads, initialises, and runs a single WASM
// debuglet module. One Debuglet instance corresponds to one session.
type Debuglet struct {
	logger *zap.SugaredLogger
	engine *wasmer.Engine
	store  *wasmer.Store

	wasiEnv        wasmer.WasiEnvironment
	wasmerInstance *wasmer.Instance

	scionServer pan.ListenConn
	udpServer   net.PacketConn
	tcpServer   *net.TCPListener

	// addresses is the list of peer addresses made available to the WASM module.
	addresses []string

	started bool
	hostEnv HostEnvironment

	createdAt time.Time
	mu        sync.Mutex

	// stdoutCh buffers WASI stdout/stderr chunks while the debuglet runs.
	stdoutCh chan []byte
	closed   bool
}

// NewDebuglet creates a ready-to-initialise Debuglet backed by a new wasmer
// Engine and Store.
func NewDebuglet(logger *zap.Logger) *Debuglet {
	eng := wasmer.NewEngine()
	return &Debuglet{
		logger:    logger.Sugar(),
		engine:    eng,
		store:     wasmer.NewStore(eng),
		createdAt: time.Now(),
		stdoutCh:  make(chan []byte, 1024),
	}
}

// StdoutChan returns the channel on which WASI stdout/stderr bytes are
// published while the debuglet executes.
func (d *Debuglet) StdoutChan() <-chan []byte {
	return d.stdoutCh
}

func (d *Debuglet) CloseStdoutChan() {
	if !d.closed {
		return
	}
	close(d.stdoutCh)
	d.closed = true
}

// Init starts the network servers and compiles and instantiates the WASM
// module. It must be called exactly once before Run.
func (d *Debuglet) Init(wasmBytes []byte, addresses []string) error {
	if err := d.startServers(); err != nil {
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
func (d *Debuglet) startServers() error {
	d.logger.Debugw("startServers: starting")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// -- Placeholder for future UDP server --
	// udpServer, err := net.ListenPacket("udp", ":0")

	// -- Placeholder for future TCP server --
	// addr, err := net.ResolveTCPAddr("tcp", ":0")
	// tcpServer, err := net.ListenTCP("tcp", addr)

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
	scionServer, err := pan.ListenUDP(context.Background(), listen.Get(), nil)
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
	d.wasiEnv = *wasiEnv

	d.logger.Debug("generating new debuglet import object")
	importObject, err := d.wasiEnv.GenerateImportObject(d.store, module)
	if err != nil {
		return fmt.Errorf("createWASMInstance: generate import object failed: %w", err)
	}

	// Per-session state shared across host function calls.
	scionConns := NewSCIONConnRegistry(scionConnCapacity)
	socketRegistry := &SocketRegistry{}
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

// wrapHostFn wraps a hostFunction with the session's HostEnvironment and
// converts it into a *wasmer.Function ready for registration.
func (d *Debuglet) wrapHostFn(
	input, output []*wasmer.ValueType,
	fn hostFunction,
) *wasmer.Function {
	return wasmer.NewFunctionWithEnvironment(
		d.store,
		wasmer.NewFunctionType(input, output),
		d.hostEnv,
		fn,
	)
}

// registerHostFunctions populates the importObject with all host functions
// that WASM modules may call. WASM-visible key strings are kept stable; only
// the Go-side implementation names have changed.
func (d *Debuglet) registerHostFunctions(
	importObject *wasmer.ImportObject,
	scionConns *SCIONConnRegistry,
	sockets *SocketRegistry,
	lastReceived *net.Addr,
) {
	i32 := wasmer.I32
	i64 := wasmer.I64
	in := wasmer.NewValueTypes
	out := wasmer.NewValueTypes

	importObject.Register("env", map[string]wasmer.IntoExtern{
		// ---- Context / timing ----
		"wait_start": d.wrapHostFn(in(), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				d.markStarted()
				return hostWaitStart(env, args)
			},
		),

		"get_timestamp": d.wrapHostFn(in(), out(i64),
			hostGetTimestamp,
		),

		"wait_until": d.wrapHostFn(in(i64), out(),
			hostWaitUntil,
		),

		// ---- TCP socket API ----
		"connect_tcp": d.wrapHostFn(in(i32), out(i32),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostConnectTCP(env, args, d.addresses, d.logger, sockets)
			},
		),

		"connect_tls": d.wrapHostFn(in(i32), out(i32),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostConnectTLS(env, args, d.addresses, d.logger, sockets, nil)
			},
		),

		"accept_tcp": d.wrapHostFn(in(), out(i32),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostAcceptTCP(env, args, d.tcpServer, d.logger, sockets)
			},
		),

		"receive_tcp_data": d.wrapHostFn(in(i32, i32), out(i32),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostReceiveTCPData(env, args, d.logger, sockets, d.wasmerInstance)
			},
		),

		"send_tcp_data": d.wrapHostFn(in(i32, i32, i32), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostSendTCPData(env, args, d.logger, sockets, d.wasmerInstance)
			},
		),

		"close_tcp": d.wrapHostFn(in(i32), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostCloseTCP(env, args, d.logger, sockets)
			},
		),

		// ---- SCION-UDP API ----
		"send_scion_udp_packet": d.wrapHostFn(in(i32, i32), out(i64),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostSendSCIONUDPPacket(env, args, scionConns, d.addresses, d.logger, d.wasmerInstance)
			},
		),

		"receive_scion_server_udp_packet": d.wrapHostFn(in(i32), out(i32, i64),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				d.markStarted()
				return hostReceiveSCIONServerUDPPacket(env, args, lastReceived, d.logger, d.wasmerInstance, &d.scionServer)
			},
		),

		"scion_available_paths": d.wrapHostFn(in(i32), out(i32),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostSCIONAvailablePaths(env, args, scionConns, d.addresses, d.logger)
			},
		),

		"scion_path_length": d.wrapHostFn(in(i32, i32), out(i32),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostSCIONPathLength(env, args, scionConns, d.addresses, d.logger)
			},
		),

		"scion_get_interface_details": d.wrapHostFn(in(i32, i32, i32), out(i64, i64),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostSCIONGetInterfaceDetails(env, args, scionConns, d.addresses, d.logger)
			},
		),

		"scion_select_path": d.wrapHostFn(in(i32, i32), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostSCIONSelectPath(env, args, scionConns, d.addresses, d.logger)
			},
		),

		// ---- Debug write API ----
		"write": d.wrapHostFn(in(i32), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostWriteString(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_noeol": d.wrapHostFn(in(i32), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostWriteStringNoEOL(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_i32": d.wrapHostFn(in(i32), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostWriteI32(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_i64": d.wrapHostFn(in(i64), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostWriteI64(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_i32x": d.wrapHostFn(in(i32), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostWriteI32Hex(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_i64x": d.wrapHostFn(in(i64), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostWriteI64Hex(env, args, d.logger, d.wasmerInstance)
			},
		),

		"write_delta_timestamp": d.wrapHostFn(in(i64), out(),
			func(env interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
				return hostWriteDeltaTimestamp(env, args, d.logger)
			},
		),
	})
}

// Close shuts down all network listeners and the wasmer instance.
func (d *Debuglet) Close() {
	if d.scionServer != nil {
		_ = d.scionServer.Close()
	}
	if d.udpServer != nil {
		_ = d.udpServer.Close()
	}
	if d.tcpServer != nil {
		_ = d.tcpServer.Close()
	}
	if d.wasmerInstance != nil {
		d.wasmerInstance.Close()
	}
	d.CloseStdoutChan()
}

// Run executes the debuglet's "run_debuglet" WASM export, streams stdout/stderr
// back through StdoutChan, and returns the result bytes written to the WASM
// result buffer.
func (d *Debuglet) Run() ([]byte, error) {
	instance := d.wasmerInstance

	runFunc, err := instance.Exports.GetFunction("run_debuglet")
	if err != nil {
		d.logger.Warnw("Run: 'run_debuglet' not exported", "err", err)
		return nil, fmt.Errorf("run_debuglet is not correctly exported: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	defer cancel()
	d.hostEnv = HostEnvironment{ctx}

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

		resIdx, err := extractResIdx(instance)
		if err != nil {
			done <- fmt.Errorf("failed to retrieve result index: %w", err)
			return
		}

		resultSize := int32(binary.LittleEndian.Uint32(resIdx))
		result, err = getResult(instance, resultSize)
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
			d.CloseStdoutChan()
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
func (d *Debuglet) flushWASIOutput() {
	buf := d.wasiEnv.ReadStdout()
	d.stdoutCh <- buf
}
