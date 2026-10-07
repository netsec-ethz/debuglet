// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

type experimentControl func(context.Context, []byte) (wire.Experiment, error)

func (f experimentControl) Ready(ctx context.Context, metadata []byte) (wire.Experiment, error) {
	return f(ctx, metadata)
}

func TestExperimentGuest(t *testing.T) {
	module := buildGuest(t, "./pkg/debuglet/testdata/experiment")
	t.Run("poll metadata and wait", func(t *testing.T) {
		var calls atomic.Int32
		var target atomic.Int64
		control := experimentControl(func(ctx context.Context, metadata []byte) (wire.Experiment, error) {
			if string(metadata) != "guest endpoint" {
				return wire.Experiment{}, fmt.Errorf("wrong metadata %q", metadata)
			}
			if calls.Add(1) == 1 {
				return wire.Experiment{ID: "batch"}, nil
			}
			target.Store(time.Now().Add(400 * time.Millisecond).UnixNano())
			return wire.Experiment{ID: "batch", StartTimeNS: target.Load(), Participants: []wire.ExperimentParticipant{{ID: "peer", ExecutorID: "executor", Metadata: []byte("peer endpoint")}}}, nil
		})
		g := runGuest(t, module, hostOptions{experiment: control, args: []string{"ready"}})
		requireSuccess(t, g)
		requireContains(t, g, "experiment=batch members=1 peer=peer endpoint", "wait=<nil>")
		var observed, requested int64
		line := g.waitFor("wait=", 0)
		if _, err := fmt.Sscanf(line, "wait=<nil> observed=%d target=%d", &observed, &requested); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 2 || requested != target.Load() || observed < requested {
			t.Fatalf("calls=%d observed=%d target=%d", calls.Load(), observed, requested)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		control := experimentControl(func(ctx context.Context, _ []byte) (wire.Experiment, error) {
			<-ctx.Done()
			return wire.Experiment{}, ctx.Err()
		})
		g := runGuest(t, module, hostOptions{experiment: control, args: []string{"deadline"}})
		requireSuccess(t, g)
		requireContains(t, g, "deadline=true late=false")
	})
	t.Run("late", func(t *testing.T) {
		control := experimentControl(func(context.Context, []byte) (wire.Experiment, error) {
			return wire.Experiment{StartTimeNS: time.Now().Add(-time.Second).UnixNano()}, nil
		})
		g := runGuest(t, module, hostOptions{experiment: control, args: []string{"late"}})
		requireSuccess(t, g)
		requireContains(t, g, "deadline=false late=true")
	})
}

func TestWaitStartCancellationAndLate(t *testing.T) {
	if err := debuglet.WaitStart(context.Background(), wire.Experiment{StartTimeNS: time.Now().Add(-time.Second).UnixNano()}); !errors.Is(err, debuglet.ErrExperimentLate) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := debuglet.WaitStart(ctx, wire.Experiment{StartTimeNS: time.Now().Add(time.Hour).UnixNano()}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
