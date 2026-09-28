// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"sync/atomic"
	"testing"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

func TestDurableOutputCanceledCallbackFinalizesWithoutStartingProducer(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "start"
		if failed {
			name = "failed"
		}
		t.Run(name, func(t *testing.T) {
			peer := newOperationPeer()
			var streams atomic.Int32
			peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
				streams.Add(1)
				return stream.Context().Err()
			}
			e, _ := newExecutorRPCFixture(t, peer, nil)
			e.outputVersion.Store(pb.OutputVersion)
			spec := operationSpec()
			if err := e.output.Admit(t.Context(), spec.DebugletID, spec.Binding, pb.OutputVersion); err != nil {
				t.Fatal(err)
			}
			runtime := new(operationRuntime)
			installOperationRuntime(e, spec, runtime)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if failed {
				e.OnDebugletFailed(ctx, spec, context.Canceled)
			} else {
				e.OnDebugletStart(ctx, spec)
			}
			retained, err := e.output.Get(t.Context(), spec.DebugletID)
			if err != nil || retained.End == nil || retained.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE || retained.End.LastSequence != 0 || retained.End.Reason != "" || retained.EndAcknowledged || retained.LastSequence != 0 || retained.QueuedFrames != 0 || retained.Binding != spec.Binding {
				t.Fatalf("canceled callback left empty output unresolved: %+v %v", retained, err)
			}
			if runtime.starts.Load() != 0 || runtime.closes.Load() != 0 || streams.Load() != 0 {
				t.Fatal("canceled callback started producer or output delivery")
			}
		})
	}
}
