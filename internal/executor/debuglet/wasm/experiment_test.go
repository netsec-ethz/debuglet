// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type experimentControl func(context.Context, []byte) (wire.Experiment, error)

func (f experimentControl) Ready(ctx context.Context, metadata []byte) (wire.Experiment, error) {
	return f(ctx, metadata)
}

func TestExperimentHostValidatesBeforePublication(t *testing.T) {
	mod := newGuestModule(t)
	calls := 0
	env := &WasmEnv{Experiment: experimentControl(func(context.Context, []byte) (wire.Experiment, error) { calls++; return wire.Experiment{}, nil })}
	ready := hostExperimentReady(env)
	ctx := context.Background()
	deadline := time.Now().Add(time.Second).UnixNano()
	if got := ready(ctx, mod.Memory(), 0, 4097, 0, 1024, deadline); got != -4 {
		t.Fatal(got)
	}
	for _, call := range []func(){
		func() { ready(ctx, mod.Memory(), 0, 1, wasmPageSize-1, 10, deadline) },
		func() { ready(ctx, mod.Memory(), wasmPageSize, 1, 0, 1024, deadline) },
		func() { ready(ctx, mod.Memory(), 0, 1, ^uint32(0), 10, deadline) },
	} {
		if hostTrap(call) == nil {
			t.Fatal("invalid memory accepted")
		}
	}
	if got := ready(ctx, mod.Memory(), 0, 0, 0, 1024, time.Now().Add(-time.Second).UnixNano()); got != -3 {
		t.Fatal(got)
	}
	if calls != 0 {
		t.Fatalf("invalid input published %d times", calls)
	}
}

type boundedExperimentMemory struct{ Memory }

func (m boundedExperimentMemory) Read(ptr, size uint32) ([]byte, bool) {
	if size > MAX_SLICE_LENGTH {
		return nil, false
	}
	return m.Memory.Read(ptr, size)
}
func (m boundedExperimentMemory) Write(ptr uint32, data []byte) bool {
	if len(data) > MAX_SLICE_LENGTH {
		return false
	}
	return m.Memory.Write(ptr, data)
}

func TestExperimentHostChunkedResponseAndPrivateErrors(t *testing.T) {
	mod := newGuestModule(t)
	result := wire.Experiment{ID: "batch", StartTimeNS: 10, Participants: []wire.ExperimentParticipant{
		{ID: "one", Metadata: make([]byte, 4096)}, {ID: "two", Metadata: make([]byte, 4096)},
	}}
	env := &WasmEnv{Experiment: experimentControl(func(context.Context, []byte) (wire.Experiment, error) { return result, nil })}
	got := hostExperimentReady(env)(context.Background(), boundedExperimentMemory{mod.Memory()}, 0, 0, 0, 32000, time.Now().Add(time.Second).UnixNano())
	if got <= MAX_SLICE_LENGTH {
		t.Fatalf("response not chunked: %d", got)
	}
	data, _ := mod.Memory().Read(0, uint32(got))
	var decoded wire.Experiment
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded.Participants) != 2 || len(decoded.Participants[1].Metadata) != 4096 {
		t.Fatalf("invalid result %v", err)
	}
	env.Experiment = experimentControl(func(context.Context, []byte) (wire.Experiment, error) {
		return wire.Experiment{}, status.Error(codes.Unauthenticated, "secret credential")
	})
	if got := hostExperimentReady(env)(context.Background(), mod.Memory(), 0, 0, 0, 32000, time.Now().Add(time.Second).UnixNano()); got != -1 {
		t.Fatal(got)
	}
}
