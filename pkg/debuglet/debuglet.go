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
	"debuglet/pkg/shared"
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
	streamPollInterval = 100 * time.Millisecond
)

// Environment struct to pass to host functions that are exported to the wasm runtime
type HostEnvironment struct {
	ctx context.Context
}

// Checks if the Context object wrapped in a HostEnvironment has expired
func checkContext(env HostEnvironment) error {
	select {
	case <-env.ctx.Done():
		break
	default:
		return nil
	}

	switch err := env.ctx.Err(); err {
	case context.DeadlineExceeded:
		return fmt.Errorf("debuglet exceeded maximum allowed runtime")
	default:
		return fmt.Errorf("debuglet's context has been cancelled: %w", err)
	}
}

type Debuglet struct {
	logger *zap.SugaredLogger
	engine *wasmer.Engine
	store  *wasmer.Store

	wasiEnv        wasmer.WasiEnvironment
	wasmerInstance *wasmer.Instance

	scionServer pan.ListenConn
	udpServer   net.PacketConn
	tcpServer   *net.TCPListener

	started   bool
	hostEnv   HostEnvironment
	addresses []string

	createdAt time.Time

	// protect per-session state if needed
	mu sync.Mutex

	StdOutBuffer chan []byte
}

func NewDebuglet(logger *zap.Logger) *Debuglet {
	engine := wasmer.NewEngine()
	return &Debuglet{
		logger:       logger.Sugar(),
		engine:       engine,
		store:        wasmer.NewStore(engine),
		started:      false,
		createdAt:    time.Now(),
		StdOutBuffer: make(chan []byte, 1024),
	}
}

func (e *Debuglet) Init(wasmBytes []byte, addresses []string) error {
	err := e.startServers()
	if err != nil {
		return err
	}

	err = e.createWasmerInstance(wasmBytes)
	if err != nil {
		return err
	}
	e.addresses = addresses
	return nil
}

func (e *Debuglet) GetScionAddr() string {
	return e.scionServer.LocalAddr().String()
}

// Starts servers for currrent debuglet instance.
// Takes as input SCION and IP hosts to listen on, as well as port to use (and a logger object).
// Returns listener objects for UDP, TCP and SCION/UDP.
//
// WARNING: Currently only starts SCION/UDP listener, UDP and TCP listeners are not supported and nil is returned
func (e *Debuglet) startServers() error {
	e.logger.Debugw("Starting servers")

	// UNCOMMENT THIS FOR UDP SERVER
	// udpServer, err := net.ListenPacket("udp", ":"+strconv.Itoa(port-1))
	// if err != nil {
	// 	return nil, nil, nil, fmt.Errorf("failed to start UDP server: %w", err)
	// }

	// UNCOMMENT NEXT TWO BLOCKS FOR TCP SERVER
	// addr, err := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(port-1))
	// if err != nil {
	// 	_ = udpServer.Close()
	// 	return nil, nil, nil, fmt.Errorf("failed to resolve TCP address: %w", err)
	// }

	// tcpServer, err := net.ListenTCP("tcp", addr)
	// if err != nil {
	// 	_ = udpServer.Close()
	// 	return nil, nil, nil, fmt.Errorf("failed to start TCP listener: %w", err)
	// }

	scionHost, err := shared.GetScionAddr()
	if err != nil {
		return fmt.Errorf("failed to get SCION address: %w", err)
	}
	scionAddr, err := pan.ParseUDPAddr(scionHost)
	if err != nil {
		return fmt.Errorf("failed to parse SCION address: %w", err)
	}

	var listen pan.IPPortValue
	err = listen.Set(scionAddr.IP.String() + ":0")
	if err != nil {
		return fmt.Errorf("failed to set listening port for SCION listener: %w", err)
	}

	scionServer, err := pan.ListenUDP(context.Background(), listen.Get(), nil)
	if err != nil {
		return fmt.Errorf("failed to start SCION UDP listener: %w", err)
	}
	e.scionServer = scionServer

	e.logger.Debugw(
		"Started all servers successfully",
		// "UDP", udpServer.LocalAddr().String(),	// UNCOMMENT THESE IF ALSO USING TCP AND UDP
		// "TCP", tcpServer.Addr().String(),
		"SCION", scionServer.LocalAddr().String(),
	)
	return nil
}

// A function as expected by wasmer's function import mechanism.
type wasmerImportFunction func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error)

func (e *Debuglet) createWasmerInstance(wasmBytes []byte) error {
	// Initialize the wasmer runtime
	module, err := wasmer.NewModule(e.store, wasmBytes)
	if err != nil {
		e.logger.Warnw("failed loading module", "err", err)
		return fmt.Errorf("Error during module loading. Bytecode is probably malformed: %w", err)
	}

	// Build WASI environment with stdout/stderr capture
	// Optionally pass args from req.Args
	wasiEnv, err := wasmer.NewWasiStateBuilder("debuglet").
		CaptureStdout().
		CaptureStderr().
		Finalize()
	if err != nil {
		return fmt.Errorf("wasi finalize failed: %w", err)
	}
	e.wasiEnv = *wasiEnv

	importObject, err := e.wasiEnv.GenerateImportObject(e.store, module)
	if err != nil {
		return fmt.Errorf("generate import object failed: %w", err)
	}

	// Wraps host function in a wasmer function
	wrapFunction := func(input, output []*wasmer.ValueType, function wasmerImportFunction) *wasmer.Function {
		return wasmer.NewFunctionWithEnvironment(
			e.store,
			wasmer.NewFunctionType(input, output),
			e.hostEnv, function,
		)
	}

	dialedScionConnections := make([]*ScionDialWrapper, 16)
	var lastReceived *net.Addr = nil

	// Import host functions into wasm runtime
	importObject.Register(
		"env",
		map[string]wasmer.IntoExtern{
			"wait_start": wrapFunction(wasmer.NewValueTypes(), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					e.starterCheck()
					return wait_start(environment, args)
				},
			),

			"get_timestamp": wrapFunction(wasmer.NewValueTypes(), wasmer.NewValueTypes(wasmer.I64),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return get_timestamp(environment, args)
				},
			),

			"wait_until": wrapFunction(wasmer.NewValueTypes(wasmer.I64), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return wait_until(environment, args)
				},
			),

			"send_scion_udp_packet": wrapFunction(
				wasmer.NewValueTypes(wasmer.I32, wasmer.I32), wasmer.NewValueTypes(wasmer.I64),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return send_scion_udp_packet(
						environment,
						args,
						&dialedScionConnections,
						e.addresses,
						e.logger,
						e.wasmerInstance,
					)
				},
			),

			"receive_scion_server_udp_packet": wrapFunction(
				wasmer.NewValueTypes(wasmer.I32), wasmer.NewValueTypes(wasmer.I32, wasmer.I64),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					e.starterCheck()
					return receive_scion_server_udp_packet(
						environment,
						args,
						lastReceived,
						e.logger,
						e.wasmerInstance,
						&e.scionServer,
					)
				},
			),

			"scion_available_paths": wrapFunction(wasmer.NewValueTypes(wasmer.I32), wasmer.NewValueTypes(wasmer.I32),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return scion_available_paths(
						environment,
						args,
						&dialedScionConnections,
						e.addresses,
						e.logger,
					)
				},
			),

			"scion_path_length": wrapFunction(
				wasmer.NewValueTypes(wasmer.I32, wasmer.I32), wasmer.NewValueTypes(wasmer.I32),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return scion_path_length(
						environment,
						args,
						&dialedScionConnections,
						e.addresses,
						e.logger,
					)
				},
			),

			"scion_get_interface_details": wrapFunction(
				wasmer.NewValueTypes(wasmer.I32, wasmer.I32, wasmer.I32), wasmer.NewValueTypes(wasmer.I64, wasmer.I64),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return scion_get_interface_details(
						environment,
						args,
						&dialedScionConnections,
						e.addresses,
						e.logger,
					)
				},
			),

			"scion_select_path": wrapFunction(wasmer.NewValueTypes(wasmer.I32, wasmer.I32), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return scion_select_path(
						environment,
						args,
						&dialedScionConnections,
						e.addresses,
						e.logger,
					)
				},
			),

			"write": wrapFunction(wasmer.NewValueTypes(wasmer.I32), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return write(
						environment,
						args,
						e.logger,
						e.wasmerInstance,
					)
				},
			),

			"write_noeol": wrapFunction(wasmer.NewValueTypes(wasmer.I32), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return write_noeol(
						environment,
						args,
						e.logger,
						e.wasmerInstance,
					)
				},
			),

			"write_i32": wrapFunction(wasmer.NewValueTypes(wasmer.I32), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return write_i32(
						environment,
						args,
						e.logger,
						e.wasmerInstance,
					)
				},
			),

			"write_i64": wrapFunction(wasmer.NewValueTypes(wasmer.I64), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return write_i64(
						environment,
						args,
						e.logger,
						e.wasmerInstance,
					)
				},
			),

			"write_i32x": wrapFunction(wasmer.NewValueTypes(wasmer.I32), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return write_i32x(
						environment,
						args,
						e.logger,
						e.wasmerInstance,
					)
				},
			),

			"write_i64x": wrapFunction(wasmer.NewValueTypes(wasmer.I64), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return write_i64x(
						environment,
						args,
						e.logger,
						e.wasmerInstance,
					)
				},
			),

			"write_delta_timestamp": wrapFunction(wasmer.NewValueTypes(wasmer.I64), wasmer.NewValueTypes(),
				func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
					return write_delta_timestamp(
						environment,
						args,
						e.logger,
					)
				},
			),
		},
	)

	// Yet more wasmer initialization
	instance, err := wasmer.NewInstance(module, importObject)
	if err != nil {
		e.logger.Warnw("failed to instantiate wasm executor", "err", err)
		return fmt.Errorf("failed to instantiate wasm executor: %w", err)
	}
	e.wasmerInstance = instance
	return nil
}

func (e *Debuglet) Close() {
	if e.scionServer != nil {
		_ = e.scionServer.Close()
	}
	if e.udpServer != nil {
		_ = e.udpServer.Close()
	}
	if e.tcpServer != nil {
		_ = e.tcpServer.Close()
	}
	if e.wasmerInstance != nil {
		e.wasmerInstance.Close()
	}
	close(e.StdOutBuffer)
}

func (e *Debuglet) Run() ([]byte, error) {
	instance := e.wasmerInstance
	// tcpConnectionList := make([]*ConnWrapper, 8)		// UNCOMMENT THIS IF YOU WANT TO USE TCP

	// var lastUdpReceived *net.Addr = nil
	// lastUdpReceived = lastUdpReceive

	// Get exported `run_debuglet` function. This is essentially the debuglet's "main"
	debuglet, err := instance.Exports.GetFunction("run_debuglet")
	if err != nil {
		e.logger.Warnw("failed to get 'run_debuglet' function", "err", err)
		return nil, fmt.Errorf("run_debuglet is not correctly exported: %w", err)
	}

	// Initialize context for execution timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	e.hostEnv = HostEnvironment{ctx}

	var retErr error
	var result []byte

	// Channel to report process completion and error
	done := make(chan error, 1)

	// Run the instance in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				e.logger.Errorf("Debuglet recovered from panic: %v", r)
				// optionally log stack trace:
				// debug.PrintStack()
				done <- fmt.Errorf("error running debuglet: %w", r)
			}
		}()
		// Call _start() (WASI convention). This will run until the module exits or is interrupted.
		// Run the debuglet, catch potential errors
		_, debugletRunErr := debuglet()
		if debugletRunErr != nil {
			e.logger.Warnw("failed running debuglet", "err", debugletRunErr)
			done <- fmt.Errorf("error running debuglet: %w", debugletRunErr)
			return
		}

		resIdx, err := extractResIdx(instance)
		if err != nil {
			done <- fmt.Errorf("%w %w",
				fmt.Errorf("error running debuglet: %w", debugletRunErr),
				fmt.Errorf("was not able to retrieve result index: %w", err),
			)
			return
		}

		// Extract the result from the wasm runtime
		resultSize := int32(binary.LittleEndian.Uint32(resIdx))
		result, err = getResult(instance, resultSize)
		if err != nil {
			e.logger.Warnw("failed retrieving result", "err", err)
			done <- fmt.Errorf("Error retrieving result: %w", err)
			return
		}
		done <- debugletRunErr
	}()

	// Poll wasi env for stdout/stderr and forward to stream until program exit or ctx cancellation
	ticker := time.NewTicker(streamPollInterval)
	defer ticker.Stop()

StreamingLoop:
	for {
		select {
		case <-ctx.Done():
			// client cancelled; attempt to stop instance and return
			// instance.Close() typically interrupts execution; behavior should be tested
			retErr = ctx.Err()
			break StreamingLoop
		case err := <-done:
			// Program finished. Flush remaining output and then send final status.
			if err != nil {
				// stream any final output before sending error status
				e.flushWasiOutput()
				retErr = err
				break StreamingLoop
			}
			// flush remaining stdout/stderr
			e.flushWasiOutput()
			break StreamingLoop
		case <-ticker.C:
			// Read available stdout/stderr and stream them
			e.flushWasiOutput()
			break StreamingLoop
		}
	}
	return result, retErr
}

func (e *Debuglet) starterCheck() {
	if !e.started {
		e.started = true
	}
}

func (e *Debuglet) flushWasiOutput() {
	buf := e.wasiEnv.ReadStdout()
	e.StdOutBuffer <- buf
}
