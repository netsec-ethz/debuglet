// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// Each participant runs the real WASI guest with its own admitted TCP listener,
// socket registry, destination policy and fallback limiter.
func TestWorkflowBarrierGuests(t *testing.T) {
	module := buildGuest(t, "./pkg/debuglet/testdata/workflow_barrier")
	for _, scenario := range []string{"repeated", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			metadata := map[string][]byte{}
			var start int64
			participants := []string{"a", "b", "c"}
			runs := make([]*guestRun, 0, len(participants))
			for _, participant := range participants {
				control := experimentControl(func(_ context.Context, value []byte) (wire.Experiment, error) {
					mu.Lock()
					defer mu.Unlock()
					metadata[participant] = append([]byte(nil), value...)
					group := wire.Experiment{ID: "barrier-group"}
					if len(metadata) < len(participants) {
						return group, nil
					}
					if start == 0 {
						start = time.Now().Add(time.Second).UnixNano()
					}
					group.StartTimeNS = start
					for _, peer := range participants {
						group.Participants = append(group.Participants, wire.ExperimentParticipant{
							ID: "run-" + peer, ExecutorID: "executor-" + peer, Metadata: metadata[peer],
						})
					}
					return group, nil
				})
				runs = append(runs, startGuest(t, module, hostOptions{
					experiment: control, addresses: []string{loopback}, listenTCP: true,
					args: []string{participant, scenario}, budget: 60 * time.Second,
				}))
			}
			for i, run := range runs {
				if !run.wait(30 * time.Second) {
					t.Fatalf("participant %s did not finish: %s", participants[i], run.output())
				}
				requireSuccess(t, run)
				requireContains(t, run, "barrier scenario complete")
				phases := map[string][]float64{}
				for _, line := range strings.Split(run.output(), "\n") {
					if !strings.HasPrefix(line, "{") {
						continue
					}
					var result struct {
						Phase      string  `json:"phase"`
						Generation float64 `json:"generation"`
					}
					if err := json.Unmarshal([]byte(line), &result); err != nil {
						t.Fatal(err)
					}
					phases[result.Phase] = append(phases[result.Phase], result.Generation)
				}
				if scenario == "repeated" {
					if got := phases["sample"]; len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
						t.Fatalf("participant %s repeated phases: %v", participants[i], phases)
					}
					if participants[i] == "b" {
						requireContains(t, run, "user message preserved")
					}
				} else if participants[i] != "c" {
					if got := phases["missing"]; len(got) != 2 || got[0] != 1 || got[1] != 2 || len(phases["recovery"]) != 1 {
						t.Fatalf("participant %s timeout recovery: %v", participants[i], phases)
					}
				}
			}
		})
	}
}
