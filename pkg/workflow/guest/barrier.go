// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

const experimentBarrierLimit = 64

type experimentBarrierArrival struct {
	Phase      string `json:"phase"`
	Generation uint64 `json:"generation"`
}

// At most the active and immediately following generation can have arrivals.
// A fast participant may enter the next generation before we consume the last
// arrival of the current one; its two arrivals must remain independent.
type experimentBarrierState struct {
	generation    uint64
	current, next map[string]bool
}

// Barrier announces this participant's arrival and waits for every other
// admitted participant to enter the same phase and generation. A successful
// result proves those arrivals, not that peers received this participant's
// announcement or returned successfully themselves. No clocks are synchronized.
func (e *Experiment) Barrier(inputs map[string]any) (map[string]any, error) {
	phase, err := networkString(inputs, "phase", "")
	if err != nil || !validBarrierPhase(phase) {
		return nil, fmt.Errorf("phase must contain 1–64 characters without surrounding whitespace")
	}
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	if e.id == "" {
		return nil, fmt.Errorf("phase barrier requires an admitted experiment")
	}
	state, err := e.barrierState(phase)
	if err != nil {
		return nil, err
	}
	if state.generation >= 1000 {
		return nil, fmt.Errorf("phase barrier exceeds 1000 generations")
	}
	state.generation++
	state.current, state.next = state.next, map[string]bool{}
	start := time.Now()
	deadline := start.Add(timeout)
	out := map[string]any{"ok": false, "error": "", "phase": phase, "generation": float64(state.generation), "missing": []any{}, "duration_ms": float64(0)}
	defer networkDuration(out, start)
	defer func() { out["missing"] = e.barrierMissing(state) }()
	peers := make([]string, 0, len(e.peers)-1)
	for peer := range e.peers {
		if peer != e.participant {
			peers = append(peers, peer)
		}
	}
	slices.Sort(peers)
	for _, peer := range peers {
		frame := experimentFrame{
			ExperimentID: e.id, Fingerprint: e.fingerprint, From: e.participant,
			FromRunID: e.peers[e.participant].runID, To: peer, ToRunID: e.peers[peer].runID,
			Sequence: state.generation, Barrier: &experimentBarrierArrival{phase, state.generation},
		}
		if err := e.writeFrame(frame, deadline); err != nil {
			out["error"] = fmt.Sprintf("announce phase to %s: %v", peer, err)
			return out, nil
		}
	}
	for len(state.current) < len(peers) {
		if time.Until(deadline) <= 0 {
			out["error"] = "phase barrier timed out"
			return out, nil
		}
		if err := e.receiveFrame(deadline); err != nil {
			out["error"] = err.Error()
			return out, nil
		}
	}
	out["ok"] = true
	return out, nil
}

func validBarrierPhase(phase string) bool {
	return len(phase) > 0 && len(phase) <= 64 && strings.TrimSpace(phase) == phase
}

func (e *Experiment) barrierState(phase string) (*experimentBarrierState, error) {
	state := e.barriers[phase]
	if state == nil {
		if len(e.barriers) >= experimentBarrierLimit {
			return nil, fmt.Errorf("experiment exceeds 64 named barrier phases")
		}
		state = &experimentBarrierState{current: map[string]bool{}, next: map[string]bool{}}
		e.barriers[phase] = state
	}
	return state, nil
}

func (e *Experiment) barrierMissing(state *experimentBarrierState) []any {
	missing := []string{}
	for peer := range e.peers {
		if peer != e.participant && !state.current[peer] {
			missing = append(missing, peer)
		}
	}
	slices.Sort(missing)
	values := make([]any, len(missing))
	for i, peer := range missing {
		values[i] = peer
	}
	return values
}

func (e *Experiment) enqueueBarrier(frame experimentFrame, size int) error {
	arrival := frame.Barrier
	if size < 1 || size > experimentFrameLimit || !validBarrierPhase(arrival.Phase) ||
		arrival.Generation == 0 || arrival.Generation > 1000 || frame.Sequence == 0 ||
		frame.Channel != "" || frame.RequestID != "" || frame.Value != nil {
		return fmt.Errorf("invalid phase barrier arrival")
	}
	if e.barriers[arrival.Phase] == nil && arrival.Generation != 1 {
		return nil
	}
	state, err := e.barrierState(arrival.Phase)
	if err != nil {
		return err
	}
	if arrival.Generation < state.generation {
		return nil // A timed-out generation cannot satisfy its successor.
	}
	arrivals := state.current
	if arrival.Generation == state.generation+1 {
		arrivals = state.next
	} else if arrival.Generation != state.generation {
		return nil // Skipped phases must not fail an unrelated message wait.
	}
	if arrivals[frame.From] {
		return nil // Repeated delivery is idempotent within this generation.
	}
	// Phase, generation and sender provide their own bounded replay identity.
	// Barrier traffic must not advance the application's sequence window.
	arrivals[frame.From] = true
	return nil
}

func (e *Experiment) writeFrame(frame experimentFrame, deadline time.Time) error {
	data, err := experimentEncode(frame)
	if err != nil {
		return err
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return debuglet.ErrTimeout
	}
	conn, err := debuglet.DialTimeout("tcp", e.peers[frame.To].address, remaining)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return experimentWrite(conn, data)
}

func (e *Experiment) receiveFrame(deadline time.Time) error {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return debuglet.ErrTimeout
	}
	conn, err := debuglet.AcceptTCPTimeout(remaining)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	frame, size, err := experimentRead(conn)
	if err != nil {
		return err
	}
	return e.enqueue(frame, size)
}
