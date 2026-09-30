// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRawUploadQuotaKeepsCancellationAvailable(t *testing.T) {
	db := newFixtureDatabase(t)
	storage, err := sqlite.NewStorage(db, nil, func(controlsession.Binding) bool { return false }, fixtureAdmission(), scheduler.QueueLimits{Runs: 1, Bytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := storage.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	_, client := newExecutorRPCFixture(t, newOperationPeer(), storage)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, second := boundsUploadRequest(), boundsUploadRequest()
	first.StartTime = timestamppb.New(time.Now().Add(time.Hour))
	second.StartTime = first.StartTime
	if _, err := client.Upload(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Upload(ctx, second); status.Code(err) != codes.ResourceExhausted || status.Convert(err).Message() != "executor retained queue limit reached" {
		t.Fatalf("queue refusal=%v", err)
	}
	// Repeating an admitted identity never adds a slot or releases its owner.
	if _, err := client.Upload(ctx, first); err == nil || status.Code(err) == codes.ResourceExhausted {
		t.Fatalf("duplicate upload=%v", err)
	}
	if _, err := client.Abort(ctx, &pb.AbortRequest{DebugletId: first.Id}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Upload(ctx, second); err != nil {
		t.Fatal(err)
	}
}

func TestUploadDecodedModuleLimitPrecedesStorage(t *testing.T) {
	storage := &uploadBindingScheduler{abortTestScheduler: &abortTestScheduler{}}
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
	req := boundsUploadRequest()
	req.Wasm = make([]byte, scheduler.MaxModuleBytes+1)
	if _, err := e.OnUpload(t.Context(), operationBinding(), req); status.Code(err) != codes.ResourceExhausted || status.Convert(err).Message() != "executor upload size limit reached" {
		t.Fatalf("upload refusal=%v", err)
	}
	if len(storage.inserted) != 0 {
		t.Fatal("oversized module reached scheduler")
	}
	req.Wasm = req.Wasm[:scheduler.MaxModuleBytes]
	if _, err := e.OnUpload(t.Context(), operationBinding(), req); err != nil {
		t.Fatalf("boundary upload=%v", err)
	}
	if len(storage.inserted) != 1 {
		t.Fatal("boundary module did not reach scheduler")
	}
}
