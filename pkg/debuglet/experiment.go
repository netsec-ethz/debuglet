// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "time"

 "github.com/netsec-ethz/debuglet/pkg/wire"
)

// MaxExperimentMetadata is the opaque metadata allowance for one participant.
const MaxExperimentMetadata = wire.MaxExperimentMetadata
const experimentBufferBytes = 1 << 20

// ErrExperimentLate means the agreed start passed before the guest could wait.
var ErrExperimentLate = errors.New("debuglet: experiment start already passed")
var ErrExperimentUnavailable = errors.New("debuglet: experiment readiness unavailable or refused")

// Ready publishes immutable metadata for this run and waits for every run in its
// submitted batch. Listeners and application setup should be ready first. The
// host supplies run identity and authorization; metadata grants no network access.
// Waiting is limited to 30 seconds, the caller's deadline and the run's lifetime.
// Cancellation is checked between bounded host calls (at most one second each).
func Ready(ctx context.Context, metadata []byte) (wire.Experiment, error) {
 var result wire.Experiment
 if len(metadata) > MaxExperimentMetadata { return result, ErrTooLarge }
 ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
 defer cancel()
 buf := make([]byte, experimentBufferBytes)
 for {
  if err := ctx.Err(); err != nil { return result, err }
  deadline, _ := ctx.Deadline()
  n := experimentReady(metadata, buf, deadline.UnixNano())
  if err := ctx.Err(); err != nil { return result, err }
  switch n {
  case -2: return result, context.Canceled
  case -3: return result, context.DeadlineExceeded
  case -4: return result, ErrTooLarge
  }
  if n < 0 { return result, ErrExperimentUnavailable }
  if int(n) > len(buf) { return result, fmt.Errorf("debuglet: invalid experiment response length") }
  if err := json.Unmarshal(buf[:n], &result); err != nil { return result, fmt.Errorf("debuglet: invalid experiment response: %w", err) }
  if result.StartTimeNS != 0 {
   if result.StartTimeNS <= time.Now().UnixNano() { return result, ErrExperimentLate }
   return result, nil
  }
  timer := time.NewTimer(100*time.Millisecond)
  select {
  case <-ctx.Done(): timer.Stop(); return result, ctx.Err()
  case <-timer.C:
  }
 }
}

// WaitStart waits for the agreed wall-clock time. It rejects a start already in
// the past; callers should record their observed start themselves. This helper
// cannot guarantee synchronized clocks or simultaneous execution across hosts.
func WaitStart(ctx context.Context, experiment wire.Experiment) error {
 if err := ctx.Err(); err != nil { return err }
 delay := time.Until(time.Unix(0, experiment.StartTimeNS))
 if experiment.StartTimeNS <= 0 || delay <= 0 { return ErrExperimentLate }
 timer := time.NewTimer(delay)
 defer timer.Stop()
 select {
 case <-ctx.Done(): return ctx.Err()
 case <-timer.C: return ctx.Err()
 }
}
