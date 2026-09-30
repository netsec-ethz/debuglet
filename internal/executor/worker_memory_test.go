// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSharedMemoryBudgetKeepsGuestAndControlResponsive(t *testing.T) {
	cfg := sharedWorkerConfig(t)
	cfg.RunMemoryBytes = 64 << 20
	cfg.MemoryPages = 1024
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

	// This small valid module fills its 64MiB linear memory once. Its owned
	// cgroup has the same 64MiB limit, including runtime overhead; the node's
	// larger worker budget and separate control reserve remain available.
	module := []byte{
		0, 97, 115, 109, 1, 0, 0, 0,
		1, 4, 1, 96, 0, 0, // () -> ()
		3, 2, 1, 0, // one function
		5, 4, 1, 0, 128, 8, // 1024 memory pages
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0,
	}
	body := []byte{0, 65, 0, 65, 1, 65, 128, 128, 128, 32, 252, 11, 0, 11}
	module = append(module, 10, byte(len(body)+2), 1, byte(len(body)))
	module = append(module, body...)
	failed := operationSpec()
	failed.Wasm, failed.Policy.Timeout = module, 10*time.Second
	call := startOperationTest(t, e, failed)
	ctx, cancel := context.WithTimeout(t.Context(), operationTestBound)
	defer cancel()
	queued := boundsUploadRequest()
	queued.StartTime = timestamppb.New(time.Now().Add(time.Hour))
	if _, err := control.Upload(ctx, queued); err != nil {
		t.Fatal("control during guest memory budget:", err)
	}
	if _, err := control.Abort(ctx, &pb.AbortRequest{DebugletId: queued.Id}); err != nil {
		t.Fatal("control cleanup:", err)
	}
	if !operationAwait(t, call.done, "memory-limited worker disposal") {
		return
	}
	if call.completion.CleanupErr != nil {
		t.Fatal(call.completion.CleanupErr)
	}
	if report := operationReport(t, peer, failed.DebugletID); report.ExitCode != -1 || report.GetErrorMessage() != "execution resource budget exceeded" {
		t.Fatalf("memory budget outcome=%v", report)
	}

	// The same supervisor, phase limits, RPC session and daemon admit another
	// ordinary guest after the memory failure and joined child cleanup.
	sibling := operationSpec()
	sibling.Wasm = []byte{0, 97, 115, 109, 1, 0, 0, 0}
	healthy := startOperationTest(t, e, sibling)
	if !operationAwait(t, healthy.done, "healthy guest after memory budget") {
		return
	}
	if healthy.completion.CleanupErr != nil {
		t.Fatal(healthy.completion.CleanupErr)
	}
	select {
	case report := <-peer.reports:
		if report.DebugletId != sibling.DebugletID.String() || report.ExitCode != 0 {
			t.Fatalf("sibling outcome=%v", report)
		}
	case <-time.After(operationTestBound):
		t.Fatal("sibling terminal report missing")
	}
	queued = boundsUploadRequest()
	queued.StartTime = timestamppb.New(time.Now().Add(time.Hour))
	if _, err := control.Upload(ctx, queued); err != nil {
		t.Fatal("control after guest memory budget:", err)
	}
	if _, err := control.Abort(ctx, &pb.AbortRequest{DebugletId: queued.Id}); err != nil {
		t.Fatal("control cleanup after guest:", err)
	}
}
