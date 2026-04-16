// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/wasmerio/wasmer-go/wasmer"
)

// newHostEnv is a convenience helper that wraps a context in a HostEnvironment.
func newHostEnv(ctx context.Context) HostEnvironment {
	return HostEnvironment{ctx: ctx}
}

// =============================================================================
// checkContextExpired
// =============================================================================

// TestCheckContextExpiredActive verifies that an active context does not return
// an error.
func TestCheckContextExpiredActive(t *testing.T) {
	env := newHostEnv(context.Background())
	if err := checkContextExpired(env); err != nil {
		t.Errorf("expected nil error for active context, got: %v", err)
	}
}

// TestCheckContextExpiredCancelled verifies that a cancelled context returns a
// non-nil error.
func TestCheckContextExpiredCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	env := newHostEnv(ctx)
	if err := checkContextExpired(env); err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

// TestCheckContextExpiredDeadlineExceeded verifies that an already-expired
// deadline returns the correct error message.
func TestCheckContextExpiredDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	env := newHostEnv(ctx)
	err := checkContextExpired(env)
	if err == nil {
		t.Fatal("expected error for exceeded deadline, got nil")
	}
	want := "debuglet exceeded maximum allowed runtime"
	if err.Error() != want {
		t.Errorf("error message: want %q, got %q", want, err.Error())
	}
}

// =============================================================================
// hostWaitStart
// =============================================================================

func TestHostWaitStartActive(t *testing.T) {
	env := newHostEnv(context.Background())
	vals, err := hostWaitStart(env, []wasmer.Value{})
	if err != nil {
		t.Fatalf("hostWaitStart returned error: %v", err)
	}
	if len(vals) != 0 {
		t.Errorf("expected empty return values, got %d", len(vals))
	}
}

func TestHostWaitStartCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	env := newHostEnv(ctx)
	_, err := hostWaitStart(env, []wasmer.Value{})
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

// =============================================================================
// hostGetTimestamp
// =============================================================================

// TestHostGetTimestamp verifies that the returned nanosecond timestamp is close
// to time.Now().
func TestHostGetTimestamp(t *testing.T) {
	env := newHostEnv(context.Background())
	before := time.Now().UnixNano()

	vals, err := hostGetTimestamp(env, []wasmer.Value{})
	if err != nil {
		t.Fatalf("hostGetTimestamp returned error: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("expected 1 return value, got %d", len(vals))
	}

	ts := vals[0].I64()
	after := time.Now().UnixNano()

	if ts < before || ts > after {
		t.Errorf("timestamp %d outside expected range [%d, %d]", ts, before, after)
	}
}

// =============================================================================
// hostWaitUntil
// =============================================================================

// TestHostWaitUntilPast verifies that waiting until a past timestamp returns
// immediately.
func TestHostWaitUntilPast(t *testing.T) {
	env := newHostEnv(context.Background())
	pastNs := wasmer.NewI64(time.Now().Add(-time.Second).UnixNano())

	start := time.Now()
	_, err := hostWaitUntil(env, []wasmer.Value{pastNs})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("hostWaitUntil returned error: %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("hostWaitUntil for past timestamp took too long: %v", elapsed)
	}
}

// TestHostWaitUntilShortFuture verifies that waiting a short duration
// blocks for approximately the right amount of time.
func TestHostWaitUntilShortFuture(t *testing.T) {
	env := newHostEnv(context.Background())
	wait := 50 * time.Millisecond
	targetNs := wasmer.NewI64(time.Now().Add(wait).UnixNano())

	start := time.Now()
	_, err := hostWaitUntil(env, []wasmer.Value{targetNs})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("hostWaitUntil returned error: %v", err)
	}
	// Allow generous tolerance for CI environments.
	if elapsed < wait/2 {
		t.Errorf("hostWaitUntil returned too early: elapsed %v, expected ~%v", elapsed, wait)
	}
}

// TestHostWaitUntilContextCancelled verifies that a cancelled context
// interrupts a long wait.
func TestHostWaitUntilContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	env := newHostEnv(ctx)

	// Schedule cancellation after 20 ms.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	// Wait until 10 seconds in the future — should be interrupted.
	targetNs := wasmer.NewI64(time.Now().Add(10 * time.Second).UnixNano())
	start := time.Now()
	_, err := hostWaitUntil(env, []wasmer.Value{targetNs})
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error when context is cancelled, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("hostWaitUntil did not respect context cancellation: elapsed %v", elapsed)
	}
}

// =============================================================================
// WASMExitError
// =============================================================================

func TestWASMExitErrorKnownCodes(t *testing.T) {
	cases := []struct {
		code    int32
		wantMsg string
	}{
		{1, "failed to write to specified UDP address"},
		{4, "failed to dial TCP address"},
		{10, "failed to dial TLS address"},
		{20, "failed to dial UDP address"},
		{30, "failed to open raw socket"},
		{100, "failed to dial SCION address"},
		{500, "memory buffer is not correctly exported"},
	}

	for _, c := range cases {
		e := NewWASMExitError(c.code)
		if e.Error() != c.wantMsg {
			t.Errorf("code %d: want %q, got %q", c.code, c.wantMsg, e.Error())
		}
		if e.Code() != c.code {
			t.Errorf("Code() for %d: want %d, got %d", c.code, c.code, e.Code())
		}
	}
}

func TestWASMExitErrorUnknownCode(t *testing.T) {
	e := NewWASMExitError(9999)
	if e.Error() == "" {
		t.Error("Error() returned empty string for unknown code")
	}
}
