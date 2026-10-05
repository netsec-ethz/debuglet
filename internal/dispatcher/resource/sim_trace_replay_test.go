// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package resource_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
)

// testdata/sim-trace-congestion-seed7.json is the trace the Debuglet simulator
// (commit e918b0c1) writes for `go run . -scenario congestion -seed 7 -trace
// FILE`. Its scenario events are replayed here into the dispatcher's
// destination accounting, and core's admission decisions are compared with
// the simulator's. Only the JSON fields the replay needs are decoded.
const (
	simTraceDigest = "b2f51d7e28deb45f6dfc22f34e15b0fbcc655125164e9b673c7e36ba93a86b2b"
	// simTraceSHA256 pins the whole fixture file.
	simTraceSHA256 = "67c26fa00727c98a5d7996a0c7e68fde24daeee875ac071c4fb6eae915696294"
)

type simJob struct {
	ID           string          `json:"id"`
	Executor     string          `json:"executor"`
	Floor        bitrate.Bitrate `json:"floor"`
	Ceil         bitrate.Bitrate `json:"ceil"`
	Destinations []string        `json:"destinations"`
}

type simCapacity struct {
	Target   string          `json:"target"`
	Capacity bitrate.Bitrate `json:"capacity"`
}

type simEvent struct {
	Submit            *simJob      `json:"submit"`
	Remove            string       `json:"remove"`
	UpdateExecutor    *simCapacity `json:"update_executor"`
	UpdateDestination *simCapacity `json:"update_destination"`
}

type simTrace struct {
	Scenario struct {
		Name    string `json:"name"`
		Seed    int64  `json:"seed"`
		Options struct {
			ExecutorCapacity    bitrate.Bitrate `json:"executor_capacity"`
			DestinationCapacity bitrate.Bitrate `json:"destination_capacity"`
		} `json:"options"`
		Events []json.RawMessage `json:"events"`
	} `json:"scenario"`
	Steps []struct {
		Index    int  `json:"index"`
		Rejected bool `json:"rejected"`
		Skipped  bool `json:"skipped"`
	} `json:"steps"`
	Allocations map[string]bitrate.Bitrate `json:"allocations"`
	Digest      string                     `json:"digest"`
}

// The classes of admission decisions in which core and the simulator may
// differ. The dispatcher's destination accounting holds no executor capacity,
// so where the simulator refuses a job because its executor is full core
// admits it; and the simulator's multi v1 filter does not bound jobs by
// destination capacity, so where a destination is full core refuses a job the
// simulator admits. Any other difference fails the replay.
const (
	divergenceExecutorFull    = "simulator refuses by executor capacity, core admits"
	divergenceDestinationFull = "core refuses by destination capacity, simulator admits"
)

func TestReplaySimulatorTraceAgainstDestinationAccounting(t *testing.T) {
	raw, err := os.ReadFile("testdata/sim-trace-congestion-seed7.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != simTraceSHA256 {
		t.Fatalf("fixture SHA-256 is %x, want %s", sum, simTraceSHA256)
	}
	var trace simTrace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatal(err)
	}
	if trace.Digest != simTraceDigest || len(trace.Steps) != len(trace.Scenario.Events) {
		t.Fatalf("unexpected fixture: digest %s, %d steps for %d events", trace.Digest, len(trace.Steps), len(trace.Scenario.Events))
	}
	for i, step := range trace.Steps {
		if step.Index != i {
			t.Fatalf("step %d carries index %d", i, step.Index)
		}
	}
	events := make([]simEvent, len(trace.Scenario.Events))
	for i, rawEvent := range trace.Scenario.Events {
		if err := json.Unmarshal(rawEvent, &events[i]); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}

	// Units: the simulator writes bit/s, the unit of internal/bitrate.
	gigabit, err := bitrate.Parse("1gbit")
	if err != nil || gigabit != bitrate.Gigabit {
		t.Fatalf("1gbit parses to %d (%v)", int64(gigabit), err)
	}
	options := trace.Scenario.Options
	if options.DestinationCapacity != gigabit || options.ExecutorCapacity != gigabit {
		t.Fatalf("scenario capacities %d and %d bit/s, want 1 Gbit/s", int64(options.ExecutorCapacity), int64(options.DestinationCapacity))
	}
	for i, event := range events {
		if job := event.Submit; job != nil && (job.Floor%bitrate.Megabit != 0 || job.Ceil%bitrate.Megabit != 0 ||
			!bitrate.InPolicyRange(int64(job.Floor)) || !bitrate.InPolicyRange(int64(job.Ceil))) {
			t.Fatalf("event %d: floor %d and ceiling %d bit/s are not whole Mbit/s policy values", i, int64(job.Floor), int64(job.Ceil))
		}
	}

	usage := resource.NewDestinations(options.DestinationCapacity)
	executorCapacity := map[string]bitrate.Bitrate{}
	for _, event := range events {
		if event.Submit != nil {
			executorCapacity[event.Submit.Executor] = options.ExecutorCapacity
		}
	}
	active := map[string]*simJob{}   // the jobs admitted by both sides
	touched := map[string]bool{}     // every destination core has charged so far
	coreRefused := map[string]bool{} // the jobs only the simulator admitted
	runID := func(job string) uuid.UUID { return uuid.NewSHA1(uuid.NameSpaceOID, []byte(job)) }

	// violation fails the replay with the shortest prefix of the scenario
	// that reproduces it.
	violation := func(i int, format string, args ...any) {
		t.Helper()
		prefix, _ := json.MarshalIndent(trace.Scenario.Events[:i+1], "", "  ")
		t.Fatalf("event %d: %s\nreproducing events:\n%s", i, fmt.Sprintf(format, args...), prefix)
	}
	// check states core's invariants on every destination charged so far. A
	// destination without active jobs charges nothing and shares nothing.
	check := func(i int) {
		t.Helper()
		floors := map[string]bitrate.Bitrate{}
		totals := map[[2]string][2]bitrate.Bitrate{}
		for _, job := range active {
			for _, destination := range distinct(job.Destinations) {
				floors[destination] += job.Floor
				key := [2]string{job.Executor, destination}
				totals[key] = [2]bitrate.Bitrate{totals[key][0] + job.Floor, totals[key][1] + job.Ceil}
			}
		}
		for destination := range touched {
			floor := floors[destination]
			expected := map[string]bool{}
			for key := range totals {
				if key[1] == destination {
					expected[key[0]] = true
				}
			}
			if used := usage.Used(destination); used != floor {
				violation(i, "%s charges %d, the active floors sum to %d", destination, int64(used), int64(floor))
			}
			var sum bitrate.Bitrate
			seen := map[string]bool{}
			for executor, share := range usage.Fairshare(destination) {
				if seen[executor] || !expected[executor] {
					violation(i, "%s on %s is given a share again or without an active job", executor, destination)
				}
				seen[executor] = true
				want := totals[[2]string{executor, destination}]
				if share < want[0] || share > want[1] {
					violation(i, "%s on %s is given %d, outside [%d, %d]", executor, destination, int64(share), int64(want[0]), int64(want[1]))
				}
				sum += share
			}
			for executor := range expected {
				if !seen[executor] {
					violation(i, "%s holds active jobs on %s but is given no share", executor, destination)
				}
			}
			if capacity := usage.Cap(destination); sum > capacity {
				violation(i, "shares on %s sum to %d, above the capacity %d", destination, int64(sum), int64(capacity))
			}
		}
		for key, want := range totals {
			if floor, ceil, ok := usage.Totals(key[0], key[1]); !ok || floor != want[0] || ceil != want[1] {
				violation(i, "%s on %s holds [%d, %d], the active jobs [%d, %d]", key[0], key[1], int64(floor), int64(ceil), int64(want[0]), int64(want[1]))
			}
		}
	}

	var table []string
	agree := map[string]int{}
	differ := map[string]int{}
	for i, event := range events {
		step := trace.Steps[i]
		switch {
		case event.Submit != nil:
			job := event.Submit
			before := usage.Snapshot()
			admitted := usage.Allocate(runID(job.ID), job.Executor, job.Destinations, job.Floor, job.Ceil) == nil
			if admitted {
				for _, destination := range job.Destinations {
					touched[destination] = true
				}
			}
			if admitted == !step.Rejected {
				agree[map[bool]string{true: "admitted", false: "refused"}[admitted]]++
				if admitted {
					active[job.ID] = job
				}
				break
			}
			var class string
			if admitted {
				// Keep core on the simulator's admitted set: release the
				// allocation again, which must restore the accounting exactly.
				for _, destination := range distinct(job.Destinations) {
					usage.Remove(runID(job.ID), destination)
				}
				if after := usage.Snapshot(); after != before {
					violation(i, "releasing %s does not restore the accounting:\nbefore\n%s\nafter\n%s", job.ID, before, after)
				}
				var executorFloors bitrate.Bitrate
				for _, other := range active {
					if other.Executor == job.Executor {
						executorFloors += other.Floor
					}
				}
				if executorFloors+job.Floor > executorCapacity[job.Executor] {
					class = divergenceExecutorFull
				}
			} else {
				coreRefused[job.ID] = true
				for _, destination := range distinct(job.Destinations) {
					if usage.CheckCapacity(destination, job.Floor) != nil {
						class = divergenceDestinationFull
					}
				}
			}
			differ[class]++
			table = append(table, fmt.Sprintf("%3d %s %-7s core admitted=%-5t simulator rejected=%-5t class=%q", i, job.ID, job.Executor, admitted, step.Rejected, class))
		case event.Remove != "":
			job, held := active[event.Remove]
			if coreRefused[event.Remove] {
				delete(coreRefused, event.Remove)
				held = true // the simulator holds it, core never did
				job = nil
			}
			if held == step.Skipped {
				violation(i, "core holds %s: %t, the simulator skipped its removal: %t", event.Remove, held, step.Skipped)
			}
			if job == nil {
				break
			}
			allocations := usage.ActiveAllocations()
			for _, destination := range distinct(job.Destinations) {
				usage.Remove(runID(job.ID), destination)
			}
			delete(active, job.ID)
			if released := allocations - usage.ActiveAllocations(); released != len(distinct(job.Destinations)) {
				violation(i, "removing %s released %d allocations for %d destinations", job.ID, released, len(distinct(job.Destinations)))
			}
		case event.UpdateExecutor != nil:
			executorCapacity[event.UpdateExecutor.Target] = event.UpdateExecutor.Capacity
		case event.UpdateDestination != nil:
			if strings.Contains(event.UpdateDestination.Target, "/") {
				t.Fatalf("event %d: destination prefix %s is not replayed", i, event.UpdateDestination.Target)
			}
			if err := usage.SetLimit(event.UpdateDestination.Target, event.UpdateDestination.Capacity); err != nil {
				violation(i, "core refuses the destination limit: %v", err)
			}
		default:
			t.Fatalf("event %d: unknown event %s", i, trace.Scenario.Events[i])
		}
		check(i)
	}

	held := slices.Sorted(maps.Keys(active))
	for id := range coreRefused {
		held = append(held, id)
	}
	slices.Sort(held)
	if allocated := slices.Sorted(maps.Keys(trace.Allocations)); !slices.Equal(held, allocated) {
		t.Fatalf("the replay ends holding %v, the simulator %v", held, allocated)
	}
	t.Logf("agreed: %v; differed: %v\n%s", agree, differ, strings.Join(table, "\n"))
	if differ[""] > 0 {
		t.Fatalf("admission decisions differ outside the known classes:\n%s", strings.Join(table, "\n"))
	}
}

func distinct(destinations []string) []string {
	out := slices.Clone(destinations)
	slices.Sort(out)
	return slices.Compact(out)
}
