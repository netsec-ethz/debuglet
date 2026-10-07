// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ExperimentModule is the optional readiness ABI; the base env ABI is unchanged.
const ExperimentModule = "debuglet_experiment_v1"

// ExperimentControl is the run-bound capability supplied by the executor.
// The guest can publish metadata but cannot select a run, account or session.
type ExperimentControl interface {
	Ready(context.Context, []byte) (wire.Experiment, error)
}

func hostExperimentReady(env *WasmEnv) func(context.Context, Memory, uint32, uint32, uint32, uint32, int64) int32 {
	return func(ctx context.Context, mem Memory, ptr, size, out, capacity uint32, deadlineNS int64) int32 {
		if size > wire.MaxExperimentMetadata || capacity > 1<<20 {
			return -4
		}
		// Memory is contiguous. Validate both ends before any readiness mutation,
		// without copying a megabyte through the isolated worker's memory bridge.
		if capacity == 0 || uint64(out)+uint64(capacity) > 1<<32 {
			panic("invalid experiment output buffer")
		}
		if _, ok := mem.Read(out, 1); !ok {
			panic("invalid experiment output buffer")
		}
		if _, ok := mem.Read(out+capacity-1, 1); !ok {
			panic("invalid experiment output buffer")
		}
		metadata, ok := mem.Read(ptr, size)
		if !ok {
			panic("invalid experiment metadata buffer")
		}
		if env.Experiment == nil {
			return -1
		}
		if deadlineNS <= 0 {
			return -3
		}
		callCtx, cancel := context.WithDeadline(ctx, time.Unix(0, deadlineNS))
		defer cancel()
		if err := callCtx.Err(); err != nil {
			return experimentError(err)
		}
		result, err := env.Experiment.Ready(callCtx, append([]byte(nil), metadata...))
		if err != nil {
			return experimentError(err)
		}
		if err := callCtx.Err(); err != nil {
			return experimentError(err)
		}
		data, err := json.Marshal(result)
		if err != nil {
			return -1
		}
		if len(data) > int(capacity) {
			return -4
		}
		for offset := 0; offset < len(data); {
			end := min(offset+MAX_SLICE_LENGTH, len(data))
			if !mem.Write(out+uint32(offset), data[offset:end]) {
				panic("invalid experiment output buffer")
			}
			offset = end
		}
		return int32(len(data))
	}
}

func experimentError(err error) int32 {
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return -2
	}
	if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
		return -3
	}
	if status.Code(err) == codes.ResourceExhausted {
		return -4
	}
	return -1 // Never expose transport diagnostics or authentication material.
}
