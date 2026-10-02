// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Observe entry into the actual connection read, without replacing transport,
// packet accounting, runtime, scheduler callback or cleanup behavior.
type socketReadWitness struct {
	ratelimit.PacketCount
	id      uuid.UUID
	entered chan struct{}
	once    sync.Once
}

func (w *socketReadWitness) Attach(conn net.Conn, id uuid.UUID, addr string) (net.Conn, error) {
	conn, err := w.PacketCount.Attach(conn, id, addr)
	if err != nil || id != w.id {
		return conn, err
	}
	return &socketReadConnection{Conn: conn, witness: w}, nil
}

type socketReadConnection struct {
	net.Conn
	witness *socketReadWitness
}

func (c *socketReadConnection) Read(p []byte) (int, error) {
	c.witness.once.Do(func() { close(c.witness.entered) })
	return c.Conn.Read(p)
}

func TestSocketQuotaKeepsRealGuestAndControlResponsive(t *testing.T) {
	testSocketQuotaKeepsRealGuestAndControlResponsive(t, nil)
}
func testSocketQuotaKeepsRealGuestAndControlResponsive(t *testing.T, supervisor *isolation.Supervisor) {
	peer := newOperationPeer()
	e, control := newExecutorRPCFixture(t, peer, nil)
	local := true
	e.cfg.Network.Policy.LocalTargets = &local
	guest, err := os.ReadFile("../../pkg/debuglet/testdata/abi_v1/abi_v1.wasm")
	if err != nil {
		t.Fatal(err)
	}
	blocked := operationSpec()
	blocked.Wasm = guest
	blocked.Policy.Timeout = 30 * time.Second
	witness := &socketReadWitness{PacketCount: e.packetCount, id: blocked.DebugletID, entered: make(chan struct{})}
	e.packetCount = witness
	operator, err := e.cfg.Network.Policy.Compile()
	if err != nil {
		t.Fatal(err)
	}
	// Use real runtimes with a one-socket run budget. Every run still borrows
	// the same production node-owned descriptor budget as its session.
	e.newRuntime = func(spec scheduler.Spec) runtimeDebuglet {
		local := debuglet.New(e.logger, spec.DebugletID, spec.TransactionID, spec.Policy,
			operator, e.teslaSchedule, e.limiter, e.packetCount, e.iface, e.portManager,
			socket.NewBudget(socket.Limits{LiveSockets: 1, Listeners: 1, SocketAttempts: 2}, e.socketBudget))
		if supervisor != nil {
			return debuglet.NewWorker(local, supervisor)
		}
		return local
	}
	listen := func() *net.TCPListener {
		t.Helper()
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		return listener
	}
	acceptBound := operationTestBound
	if supervisor != nil {
		acceptBound += time.Duration(supervisor.Config().CompileWallMS) * time.Millisecond
	}
	accept := func(listener *net.TCPListener) net.Conn {
		t.Helper()
		if err := listener.SetDeadline(time.Now().Add(acceptBound)); err != nil {
			t.Fatal(err)
		}
		conn, err := listener.Accept()
		if err != nil {
			select {
			case report := <-peer.reports:
				t.Logf("run ended before peer connection: %v", report)
			default:
			}
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	closedByGuest := func(conn net.Conn) {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(operationTestBound)); err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("guest connection remains open: n=%d err=%v", n, err)
		}
	}
	blockedListener := listen()
	blocked.Args = []string{"tcp_block", blockedListener.Addr().String()}
	blockedCall := startOperationTest(t, e, blocked)
	blockedConn := accept(blockedListener)
	if !operationAwait(t, witness.entered, "real guest TCP read") {
		return
	}

	quotaListener := listen()
	quota := operationSpec()
	quota.Wasm = twoSocketGuest(quotaListener.Addr().String())
	quotaCall := startOperationTest(t, e, quota)
	quotaConn := accept(quotaListener)
	if !operationAwait(t, quotaCall.done, "quota guest runtime and socket cleanup") {
		return
	}
	closedByGuest(quotaConn)
	if quotaCall.completion.CleanupErr != nil {
		t.Fatal(quotaCall.completion.CleanupErr)
	}
	select {
	case report := <-peer.reports:
		if report.DebugletId != quota.DebugletID.String() || report.ExitCode != -1 || report.GetErrorMessage() != "guest socket quota exceeded" {
			t.Fatalf("quota outcome=%v", report)
		}
	case <-time.After(operationTestBound):
		t.Fatal("quota outcome missing")
	}
	// The refused second connect never creates another peer connection.
	if err := quotaListener.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := quotaListener.Accept(); err == nil {
		conn.Close()
		t.Fatal("quota refusal connected another peer")
	}

	ctx, cancel := context.WithTimeout(t.Context(), operationTestBound)
	defer cancel()
	queued := boundsUploadRequest()
	queued.StartTime = timestamppb.New(time.Now().Add(time.Hour))
	if _, err := control.Upload(ctx, queued); err != nil {
		t.Fatal("control upload:", err)
	}
	if _, err := control.Abort(ctx, &pb.AbortRequest{DebugletId: queued.Id}); err != nil {
		t.Fatal("control cleanup:", err)
	}

	siblingListener := listen()
	sibling := operationSpec()
	sibling.Wasm, sibling.Args = guest, []string{"tcp_connect_only", siblingListener.Addr().String()}
	siblingCall := startOperationTest(t, e, sibling)
	siblingConn := accept(siblingListener)
	if !operationAwait(t, siblingCall.done, "healthy real guest under another run's quota") {
		return
	}
	closedByGuest(siblingConn)
	if siblingCall.completion.CleanupErr != nil {
		t.Fatal(siblingCall.completion.CleanupErr)
	}
	select {
	case report := <-peer.reports:
		if report.DebugletId != sibling.DebugletID.String() || report.ExitCode != 0 {
			t.Fatalf("sibling outcome=%v", report)
		}
	case <-time.After(operationTestBound):
		t.Fatal("sibling outcome missing")
	}
	select {
	case <-blockedCall.done:
		t.Fatal("blocked guest ended before cancellation")
	default:
	}
	blockedCall.cancel(context.Canceled)
	if !operationAwait(t, blockedCall.done, "blocked read and executor callback join") {
		return
	}
	closedByGuest(blockedConn)
	if blockedCall.completion.CleanupErr != nil {
		t.Fatal(blockedCall.completion.CleanupErr)
	}
	// Joining the callbacks returns every live reservation to this same node.
	reservation, err := socket.NewBudget(socket.DefaultLimits(), e.socketBudget).ReserveSocket(socket.DefaultNodeDescriptors)
	if err != nil {
		t.Fatalf("node retained descriptors after joined cleanup: %v", err)
	}
	reservation.Release()
}

// An ordinary guest opens two TCP sockets to the same owned loopback peer.
// Its one-socket fixture budget refuses the second host call. The module has
// one memory page and no loop, allocator workload or external dependencies.
func twoSocketGuest(addr string) []byte {
	module := []byte("\x00asm\x01\x00\x00\x00")
	section := func(id byte, data []byte) {
		module = append(module, id, byte(len(data)))
		module = append(module, data...)
	}
	section(1, []byte{2, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0})
	section(2, append([]byte{1, 3, 'e', 'n', 'v', 11}, append([]byte("connect_tcp"), 0, 0)...))
	section(3, []byte{1, 1})
	section(5, []byte{1, 0, 1})
	section(7, []byte{2, 6, 'm', 'e', 'm', 'o', 'r', 'y', 2, 0, 6, '_', 's', 't', 'a', 'r', 't', 0, 1})
	call := []byte{0x41, 0, 0x41, byte(len(addr)), 0x10, 0, 0x1a}
	body := append([]byte{0}, call...)
	body = append(body, call...)
	body = append(body, 0x0b)
	section(10, append([]byte{1, byte(len(body))}, body...))
	section(11, append([]byte{1, 0, 0x41, 0, 0x0b, byte(len(addr))}, []byte(addr)...))
	return module
}
