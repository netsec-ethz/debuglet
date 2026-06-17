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
	"debuglet/internal/executor/transport/rpc"
	"debuglet/pkg/tagger"
	"debuglet/pkg/tesla"

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
	policy rpc.Policy

	logger *zap.SugaredLogger

	// wazero runtime state
	runtime  wazero.Runtime
	compiled wazero.CompiledModule

	scionServer pan.ListenConn
	udpServer   net.PacketConn
	tcpServer   *net.TCPListener
	ipServer    net.Listener

	pktTagger tagger.TaggerInterface

	createdAt time.Time
	mu        sync.Mutex
}

// New creates a ready-to-initialise Debuglet backed by a wazero Runtime.
func New(logger *zap.Logger, debugletID string, policy rpc.Policy, schedule *tesla.KeySchedule) *Debuglet {
	// setup tagging
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
		id:        debugletID,
		policy:    policy,
		logger:    logger.Sugar(),
		createdAt: time.Now(),
		pktTagger: pktTagger,
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
// wazero module with WASI and all host functions registered.
func (d *Debuglet) createWASMInstance(ctx context.Context, wasmBytes []byte) error {
	d.runtime = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())

	compiled, err := d.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		d.logger.Warnw("createWASMInstance: module compile failed", "err", err)
		return fmt.Errorf("createWASMInstance: bytecode is probably malformed: %w", err)
	}
	d.compiled = compiled

	d.logger.Debug("instantiating WASI (wasi_snapshot_preview1)")
	if _, err := wasi.Instantiate(ctx, d.runtime); err != nil {
		return fmt.Errorf("createWASMInstance: WASI instantiation failed: %w", err)
	}

	// Per-session state shared across host function calls.
	scionConns := socket.NewSCIONConnRegistry(scionConnCapacity)
	socketRegistry := &socket.SocketRegistry{}
	var lastReceived net.Addr

	d.logger.Debug("building host 'env' module")
	hmb := d.runtime.NewHostModuleBuilder("env")
	hmb = d.registerHostFunctions(hmb, scionConns, socketRegistry, &lastReceived)
	if _, err := hmb.Instantiate(ctx); err != nil {
		return fmt.Errorf("createWASMInstance: host module instantiation failed: %w", err)
	}

	return nil
}

// registerHostFunctions populates the host module builder with all host functions
// that WASM modules may call. WASM-visible key strings are kept stable; only
// the Go-side implementation names have changed.
func (d *Debuglet) registerHostFunctions(hmb wazero.HostModuleBuilder, scionConns *socket.SCIONConnRegistry, sockets *socket.SocketRegistry, lastReceived *net.Addr) wazero.HostModuleBuilder {
	// ---- Generic socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(socket.SocketTypeTCP, d.logger, sockets, nil, d.pktTagger)).Export("connect_tcp")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(socket.SocketTypeTLS, d.logger, sockets, nil, d.pktTagger)).Export("connect_tls")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveData(d.logger, sockets)).Export("receive_tcp_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendData(d.logger, sockets)).Export("send_tcp_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostClose(d.logger, sockets)).Export("close_tcp")

	// ---- TCP socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostAcceptTCP(d.tcpServer, d.logger, sockets)).Export("accept_tcp")

	// ---- IP socket API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostConnect(socket.SocketTypeICMP4, d.logger, sockets, nil, d.pktTagger)).Export("connect_icmp4")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostAcceptIP(d.ipServer, d.logger, sockets)).Export("accept_icmp4")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveData(d.logger, sockets)).Export("receive_icmp4_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendData(d.logger, sockets)).Export("send_icmp4_data")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostClose(d.logger, sockets)).Export("close_icmp4")

	// ---- SCION-UDP API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSendSCIONUDPPacket(scionConns, d.logger, d.pktTagger)).Export("send_scion_udp_packet")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostReceiveSCIONServerUDPPacket(lastReceived, d.logger, &d.scionServer, d.pktTagger)).Export("receive_scion_server_udp_packet")
	// HACK: HostAnswerSCIONUDPPacket expects a list of addresses. This has been removed for the time being as the function is not being worked on or used
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostAnswerSCIONUDPPacket(lastReceived, scionConns, []string{}, d.logger, &d.scionServer, d.pktTagger)).Export("answer_scion_udp_packet")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSCIONAvailablePaths(scionConns, d.logger, d.pktTagger)).Export("scion_available_paths")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSCIONPathLength(scionConns, d.logger, d.pktTagger)).Export("scion_path_length")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSCIONGetInterfaceDetails(scionConns, d.logger, d.pktTagger)).Export("scion_get_interface_details")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostSCIONSelectPath(scionConns, d.logger, d.pktTagger)).Export("scion_select_path")

	// ---- Debug write API ----
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostWriteString(d.logger)).Export("write")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostWriteStringNoEOL(d.logger)).Export("write_noeol")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostWriteI32(d.logger)).Export("write_i32")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostWriteI64(d.logger)).Export("write_i64")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostWriteI32Hex(d.logger)).Export("write_i32x")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostWriteI64Hex(d.logger)).Export("write_i64x")
	hmb = hmb.NewFunctionBuilder().WithFunc(wasm.HostWriteDeltaTimestamp(d.logger)).Export("write_delta_timestamp")

	return hmb
}

// Close shuts down all network listeners and the wazero module instance.
func (d *Debuglet) Close(ctx context.Context) {
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
	if d.runtime != nil {
		d.runtime.Close(ctx)
	}
	if d.pktTagger != nil {
		d.pktTagger.Close()
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
func (d *Debuglet) Run(ctx context.Context, outputCh chan<- []byte) error {
	writer := &chanWriter{ch: outputCh}
	defer close(outputCh)

	config := wazero.NewModuleConfig().
		WithStdout(writer).
		WithStderr(writer).
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep().
		WithRandSource(rand.Reader)

	// start the wasm
	mod, err := d.runtime.InstantiateModule(ctx, d.compiled, config)
	if err != nil {
		return fmt.Errorf("failed to instantiate module: %w", err)
	}
	mod.Close(ctx)

	return nil

}
