// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) { debuglet.WorkerMain(); os.Exit(m.Run()) }

func sharedWorkerConfig(t *testing.T) isolation.Config {
	t.Helper()
	root := os.Getenv("DEBUGLET_TEST_CGROUP_ROOT")
	if root == "" {
		t.Skip("requires an explicitly delegated test cgroup root")
	}
	return isolation.Config{Profile: "shared", CgroupRoot: root, NodeMemoryBytes: 512 << 20, NodeCPUQuotaUS: 100000, NodePIDs: 128,
		ControlMemoryReserveBytes: 128 << 20, ControlCPUReserveUS: 25000,
		CompileMemoryBytes: 256 << 20, CompileCPUQuotaUS: 50000, CompileWallMS: 10000, CompileConcurrency: 1, CompileQueue: 1,
		RunMemoryBytes: 256 << 20, RunCPUQuotaUS: 50000, RunWallMS: 30000, WorkerPIDs: 64, MemoryPages: 1024}
}

func sharedWorkerSupervisor(t *testing.T) *isolation.Supervisor {
	t.Helper()
	supervisor, err := isolation.New(sharedWorkerConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := supervisor.Close(); err != nil {
			t.Error(err)
		}
	})
	return supervisor
}

func TestSharedSocketQuotaKeepsRealGuestAndControlResponsive(t *testing.T) {
	testSocketQuotaKeepsRealGuestAndControlResponsive(t, sharedWorkerSupervisor(t))
}

func TestSharedGuestReceivesCopiedBytesAndEOF(t *testing.T) {
	supervisor := sharedWorkerSupervisor(t)
	peer := newOperationPeer()
	captured := make(chan string, 1)
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		var text strings.Builder
		for {
			request, err := stream.Recv()
			if err == io.EOF {
				captured <- text.String()
				return nil
			}
			if err != nil {
				return err
			}
			if output := request.GetOutput(); output != nil {
				text.Write(output.Output)
			}
		}
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	e.supervisor = supervisor
	local := true
	e.cfg.Network.Policy.LocalTargets = &local
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	peerDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peerDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		request := make([]byte, 5)
		_, err = io.ReadFull(conn, request)
		if err == nil && string(request) != "PING\n" {
			err = errors.New("unexpected guest request")
		}
		if err == nil {
			_, err = conn.Write([]byte("PONG\n"))
		}
		peerDone <- err
	}()
	guest, err := os.ReadFile("../../pkg/debuglet/testdata/abi_v1/abi_v1.wasm")
	if err != nil {
		t.Fatal(err)
	}
	spec := operationSpec()
	spec.Wasm = guest
	spec.Args = []string{"tcp_exchange", listener.Addr().String()}
	spec.Policy.Timeout = 10 * time.Second
	call := startOperationTest(t, e, spec)
	select {
	case <-call.done:
	case <-time.After(15 * time.Second):
		t.Fatal("guest and network bridge did not join")
	}
	if call.completion.CleanupErr != nil {
		t.Fatal(call.completion.CleanupErr)
	}
	if report := operationReport(t, peer, spec.DebugletID); report.ExitCode != 0 {
		t.Fatalf("guest failed: %v", report)
	}
	select {
	case err := <-peerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer did not join")
	}
	select {
	case text := <-captured:
		if !strings.Contains(text, "PONG") || !strings.Contains(text, "total=5") || !strings.Contains(text, "recv eof") {
			t.Fatalf("guest memory/EOF changed: %q", text)
		}
	case <-time.After(time.Second):
		t.Fatal("guest output missing")
	}
}

func TestSharedCompilerBudgetKeepsGuestAndControlResponsive(t *testing.T) {
	cfg := sharedWorkerConfig(t)
	// Match the race-instrumented kernel lane's compiler deadline witness.
	// With a full second, this fixture can compile and run on faster hosts.
	cfg.CompileWallMS = 250
	supervisor, err := isolation.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := supervisor.Close(); err != nil {
			t.Error(err)
		}
	})
	peer := newOperationPeer()
	e, control := newExecutorRPCFixture(t, peer, nil)
	e.supervisor = supervisor
	guest, err := os.ReadFile("../../pkg/debuglet/testdata/abi_v1/abi_v1.wasm")
	if err != nil {
		t.Fatal(err)
	}
	failed := operationSpec()
	failed.Wasm = guest
	call := startOperationTest(t, e, failed)
	ctx, cancel := context.WithTimeout(t.Context(), operationTestBound)
	defer cancel()
	queued := boundsUploadRequest()
	queued.StartTime = timestamppb.New(time.Now().Add(time.Hour))
	if _, err = control.Upload(ctx, queued); err != nil {
		t.Fatal("control while compiling:", err)
	}
	if _, err = control.Abort(ctx, &pb.AbortRequest{DebugletId: queued.Id}); err != nil {
		t.Fatal("control cleanup:", err)
	}
	if !operationAwait(t, call.done, "compiler disposal and terminal report") {
		return
	}
	if call.completion.CleanupErr != nil {
		t.Fatal(call.completion.CleanupErr)
	}
	report := operationReport(t, peer, failed.DebugletID)
	if report.ExitCode != -1 || report.GetErrorMessage() != "compilation resource budget exceeded" {
		t.Fatalf("compiler outcome=%v", report)
	}
	sibling := operationSpec()
	sibling.Wasm = []byte{0, 97, 115, 109, 1, 0, 0, 0}
	healthy := startOperationTest(t, e, sibling)
	if !operationAwait(t, healthy.done, "healthy sibling after compiler budget") {
		return
	}
	if healthy.completion.CleanupErr != nil {
		t.Fatal(healthy.completion.CleanupErr)
	}
	select {
	case report = <-peer.reports:
		if report.DebugletId != sibling.DebugletID.String() || report.ExitCode != 0 {
			t.Fatalf("sibling outcome=%v", report)
		}
	case <-time.After(operationTestBound):
		t.Fatal("sibling terminal missing")
	}
}
