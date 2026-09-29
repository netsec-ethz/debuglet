// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

func TestDurableOutputRetryDoesNotBlockTerminalSettlement(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	held, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(&pb.DebugletStreamResponse{}); err != nil {
			return err
		}
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		if req.GetOutput().GetSequence() != 1 || string(req.GetOutput().GetOutput()) != "retained" {
			return errors.New("unexpected retained frame")
		}
		close(held)
		select {
		case <-release:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if err := stream.Send(&pb.DebugletStreamResponse{CommittedSequence: 1}); err != nil {
			return err
		}
		req, err = stream.Recv()
		if err != nil {
			return err
		}
		if req.GetEnd() == nil {
			return io.ErrUnexpectedEOF
		}
		return stream.Send(&pb.DebugletStreamResponse{CommittedSequence: 1, End: req.GetEnd()})
	}
	e, _ := newExecutorRPCFixture(t, peer, storage)
	e.outputVersion.Store(pb.OutputVersion)
	spec := operationSpec()
	if err := e.output.Admit(t.Context(), spec.DebugletID, spec.Binding, pb.OutputVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := e.output.Append(t.Context(), spec.DebugletID, time.Now().UTC(), []byte("retained")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.output.Finish(t.Context(), spec.DebugletID, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, ""); err != nil {
		t.Fatal(err)
	}
	if err := storage.RecordTerminal(t.Context(), scheduler.TerminalEvent{DebugletID: spec.DebugletID, Binding: spec.Binding, RecordedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); e.reconcileOutputLoop(ctx, spec.Binding) }()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		cancel()
		if !operationAwait(t, done, "output reconciliation joins") {
			<-done
		}
	})
	if !operationAwait(t, held, "retained output awaiting receipt") {
		return
	}
	e.reconcileTerminals(t.Context(), spec.Binding)
	if peer.reportCalls.Load() != 1 {
		t.Fatal("held output retry blocked independent terminal settlement")
	}
	if _, found, err := storage.RetainedTerminal(t.Context(), spec.DebugletID); err != nil || found {
		t.Fatalf("acknowledged terminal remained retained: found=%t err=%v", found, err)
	}
	output, err := e.output.Get(t.Context(), spec.DebugletID)
	if err != nil || output.EndAcknowledged || output.QueuedFrames != 1 {
		t.Fatalf("terminal settlement consumed output: %+v %v", output, err)
	}
	releaseOnce.Do(func() { close(release) })
	phase, end := context.WithTimeout(t.Context(), operationTestBound)
	defer end()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		output, err = e.output.Get(phase, spec.DebugletID)
		if err == nil && output.EndAcknowledged && output.QueuedFrames == 0 {
			break
		}
		select {
		case <-phase.Done():
			t.Fatal("released output receipt did not settle:", phase.Err())
		case <-ticker.C:
		}
	}
	if peer.reportCalls.Load() != 1 || output.Binding != spec.Binding {
		t.Fatal("output completion duplicated or retargeted terminal")
	}
}
