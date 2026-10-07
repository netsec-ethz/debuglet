// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type denialResolver map[string]string

func (r denialResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if addr, ok := r[host]; ok {
		return []netip.Addr{netip.MustParseAddr(addr)}, nil
	}
	return nil, fmt.Errorf("no such host %q", host)
}

// denialOperator is the operator policy a run of e gets: the local profile,
// sharing the destinations e's dispatcher denied.
func denialOperator(t *testing.T, e *Executor) netpolicy.Operator {
	t.Helper()
	spec := netpolicy.Defaults()
	spec.LocalTargets = true
	operator, err := netpolicy.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	return operator.WithRevocations(e.revoked)
}

func TestBandwidthDenialAppliesBeforeAcknowledgement(t *testing.T) {
	e := newFixtureExecutor(t, fixtureConfig(), newRecordingPacketCount(), newFixtureMemoryStorage(t))
	operator := denialOperator(t, e)
	const denied, kept = "denied.example", "93.184.216.8"
	apply := func(revision uint64, limits ...*pb.DestinationLimit) (*pb.BandwidthResponse, error) {
		return e.applyBandwidth(operationBinding(), &pb.BandwidthRequest{Revision: revision, Limits: limits})
	}
	refused := func() bool { return errors.Is(operator.CheckHost(denied), netpolicy.ErrDestinationDenied) }

	if reply, err := apply(1, &pb.DestinationLimit{Address: denied, Denied: true}, &pb.DestinationLimit{Address: kept, BitsLimit: 1000}); err != nil || reply.GetRevision() != 1 {
		t.Fatalf("denial snapshot: %v, %v", reply, err)
	}
	if !refused() {
		t.Fatal("the acknowledged snapshot did not deny the destination")
	}
	if err := operator.CheckAddr(netip.MustParseAddr(kept)); err != nil {
		t.Fatalf("a destination that is not denied was refused: %v", err)
	}
	// One invalid limit leaves the whole snapshot unapplied, the denial too.
	if _, err := apply(2, &pb.DestinationLimit{Address: denied}, &pb.DestinationLimit{Address: kept, BitsLimit: -1}); err == nil {
		t.Fatal("an invalid limit was acknowledged")
	}
	if !refused() {
		t.Fatal("a rejected snapshot changed the denied destinations")
	}
	// A legacy Allocate reply carries no revision and no denial: nothing changes.
	e.bandwidthRevision, e.bandwidthApplied = 0, 0
	if _, err := apply(0, &pb.DestinationLimit{Address: kept, BitsLimit: 1000}); err != nil || !refused() {
		t.Fatalf("an unrevisioned reply cleared the denial: %v", err)
	}
	// The next full snapshot without the destination allows it again.
	if reply, err := apply(3, &pb.DestinationLimit{Address: denied, BitsLimit: 1000}); err != nil || reply.GetRevision() != 3 {
		t.Fatalf("clearing snapshot: %v, %v", reply, err)
	}
	if refused() {
		t.Fatal("a snapshot without the denial left the destination denied")
	}
}

// A destination denied while a run transfers to it over TCP and UDP: the
// acknowledgement returns after those sockets are closed, the peers stop
// receiving, and the run's socket to another destination keeps working.
func TestBandwidthDenialRevokesActiveTransfers(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	e := newFixtureExecutor(t, fixtureConfig(), newRecordingPacketCount(), newFixtureMemoryStorage(t))
	e.logger = zap.New(core)
	run := uuid.New()
	policy := netpolicy.New(denialOperator(t, e), netpolicy.Run{Addresses: []string{"target.test", "127.0.0.2"}},
		netpolicy.WithResolver(denialResolver{"target.test": "127.0.0.1"}))
	registry := socket.NewSocketRegistry(socket.NewBudget(socket.DefaultLimits(), socket.NewDescriptorBudget(socket.DefaultNodeDescriptors)))
	t.Cleanup(func() { registry.CloseAll() })
	// The same registration a run makes for its own sockets.
	stop := policy.WatchRevocations(run.String(), func() int { return registry.CloseRemote(policy.Revoked) })
	defer stop()

	ctx := t.Context()
	connect := func(transport netpolicy.Transport, network, target string) (int32, net.Conn) {
		t.Helper()
		destination, err := policy.AdmitDestination(ctx, transport, target)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.Dial(network, destination.DialAddresses()[0])
		if err != nil {
			t.Fatal(err)
		}
		typ := socket.SocketTypeTCP
		if network == "udp" {
			typ = socket.SocketTypeUDP
		}
		handle, err := registry.Add(socket.NewGenericSocket(conn, typ, target))
		if err != nil {
			t.Fatal(err)
		}
		return handle, conn
	}
	listen := func(address string) net.Listener {
		t.Helper()
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		return listener
	}

	// TCP: the peer streams to the run until its writes fail.
	tcpPeer := listen("127.0.0.1:0")
	streamEnded := make(chan error, 1)
	go func() {
		conn, err := tcpPeer.Accept()
		if err != nil {
			streamEnded <- err
			return
		}
		defer conn.Close()
		chunk := make([]byte, 4096)
		for {
			if _, err := conn.Write(chunk); err != nil {
				streamEnded <- err
				return
			}
		}
	}()
	_, tcpPort, _ := net.SplitHostPort(tcpPeer.Addr().String())
	tcpHandle, _ := connect(netpolicy.TCP, "tcp", "target.test:"+tcpPort)
	tcpSocket, err := registry.Get(tcpHandle)
	if err != nil {
		t.Fatal(err)
	}
	readEnded := make(chan error, 1)
	var received atomic.Int64
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := tcpSocket.Read(buf)
			received.Add(int64(n))
			if err != nil {
				readEnded <- err
				return
			}
		}
	}()

	// UDP: the run sends datagrams to the peer until its writes fail.
	udpPeer, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpPeer.Close() })
	udpHandle, _ := connect(netpolicy.UDP, "udp", fmt.Sprintf("target.test:%d", udpPeer.LocalAddr().(*net.UDPAddr).Port))
	udpSocket, err := registry.Get(udpHandle)
	if err != nil {
		t.Fatal(err)
	}
	sendEnded := make(chan error, 1)
	go func() {
		for {
			if _, err := udpSocket.Write([]byte("probe")); err != nil {
				sendEnded <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	datagram := make([]byte, 64)
	if err := udpPeer.SetReadDeadline(time.Now().Add(operationTestBound)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := udpPeer.ReadFrom(datagram); err != nil {
		t.Fatal("no datagram before the denial:", err)
	}

	// Another destination of the same run.
	keptPeer := listen("127.0.0.2:0")
	_, keptPort, _ := net.SplitHostPort(keptPeer.Addr().String())
	keptHandle, _ := connect(netpolicy.TCP, "tcp", "127.0.0.2:"+keptPort)
	keptServer, err := keptPeer.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keptServer.Close() })

	deadline := time.Now().Add(operationTestBound)
	for received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if received.Load() == 0 {
		t.Fatal("no TCP data before the denial")
	}

	reply, err := e.applyBandwidth(operationBinding(), &pb.BandwidthRequest{Revision: 1, Limits: []*pb.DestinationLimit{
		{Address: "target.test", Denied: true}, {Address: "127.0.0.2", BitsLimit: 1_000_000},
	}})
	if err != nil || reply.GetRevision() != 1 {
		t.Fatalf("denial snapshot: %v, %v", reply, err)
	}
	// Both sockets were closed before the acknowledgement returned.
	for _, handle := range []int32{tcpHandle, udpHandle} {
		if _, err := registry.Get(handle); !errors.Is(err, socket.ErrRevoked) {
			t.Fatalf("handle %d after the acknowledgement: %v", handle, err)
		}
	}
	for name, ended := range map[string]chan error{"tcp read": readEnded, "udp send": sendEnded} {
		select {
		case err := <-ended:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("%s ended with %v, want a closed socket", name, err)
			}
		case <-time.After(operationTestBound):
			t.Fatalf("%s continued after the denial", name)
		}
	}
	select {
	case err := <-streamEnded:
		if err == nil {
			t.Fatal("tcp peer stream ended without an error")
		}
	case <-time.After(operationTestBound):
		t.Fatal("tcp peer could still send after the denial")
	}
	// Drain what was sent before the close, then nothing more arrives.
	for {
		if err := udpPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := udpPeer.ReadFrom(datagram); err != nil {
			break
		}
	}
	if err := udpPeer.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := udpPeer.ReadFrom(datagram); err == nil {
		t.Fatalf("udp peer received %d bytes after the denial", n)
	}

	// The run's other socket still carries data both ways, and the run can
	// still open sockets to a destination that is not denied.
	kept, err := registry.Get(keptHandle)
	if err != nil {
		t.Fatal("kept socket:", err)
	}
	if _, err := kept.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := keptServer.SetReadDeadline(time.Now().Add(operationTestBound)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(keptServer, make([]byte, 4)); err != nil {
		t.Fatal("kept peer:", err)
	}
	if _, err := policy.AdmitDestination(ctx, netpolicy.TCP, "target.test:"+tcpPort); !errors.Is(err, netpolicy.ErrDestinationDenied) {
		t.Fatalf("a new connection to the denied destination: %v", err)
	}
	connect(netpolicy.TCP, "tcp", "127.0.0.2:"+keptPort)

	entries := logs.FilterMessage("Destination revoked: active sockets closed").All()
	if len(entries) != 1 {
		t.Fatalf("revocation log lines = %d", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["debugletID"] != run.String() || fields["sockets"] != int64(2) {
		t.Fatalf("revocation log fields = %v", fields)
	}
}

// The production run path registers the run with the session's denied
// destinations: a real guest blocked reading from a destination that is then
// denied has that socket closed before the acknowledgement returns. The guest
// uses the legacy socket imports, which report a failed read by ending the
// run; a guest of the recoverable I/O module observes Closed instead.
func TestBandwidthDenialClosesARealRunsSocket(t *testing.T) {
	peer := newOperationPeer()
	e, _ := newExecutorRPCFixture(t, peer, nil)
	local := true
	e.cfg.Network.Policy.LocalTargets = &local
	guest, err := os.ReadFile("../../pkg/debuglet/testdata/abi_v1/abi_v1.wasm")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	spec := operationSpec()
	spec.Wasm, spec.Args = guest, []string{"tcp_block", listener.Addr().String()}
	spec.Policy.Timeout = 30 * time.Second
	witness := &socketReadWitness{PacketCount: e.packetCount, id: spec.DebugletID, entered: make(chan struct{})}
	e.packetCount = witness
	call := startOperationTest(t, e, spec)
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(operationTestBound)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal("guest did not connect:", err)
	}
	t.Cleanup(func() { conn.Close() })
	if !operationAwait(t, witness.entered, "real guest TCP read") {
		return
	}

	reply, err := e.applyBandwidth(operationBinding(), &pb.BandwidthRequest{Revision: 1, Limits: []*pb.DestinationLimit{{Address: "127.0.0.1", Denied: true}}})
	if err != nil || reply.GetRevision() != 1 {
		t.Fatalf("denial snapshot: %v, %v", reply, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(operationTestBound)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("the denied connection is still open: n=%d err=%v", n, err)
	}
	if !operationAwait(t, call.done, "run after its blocked read was revoked") {
		return
	}
	select {
	case report := <-peer.reports:
		t.Logf("legacy guest outcome: exit=%d message=%q", report.ExitCode, report.GetErrorMessage())
	case <-time.After(operationTestBound):
		t.Fatal("run outcome missing")
	}
}
