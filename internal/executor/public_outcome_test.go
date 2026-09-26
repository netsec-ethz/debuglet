// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/tetratelabs/wazero/sys"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// genericOutcome is what a run reports when its cause is the executor's own.
const genericOutcome = "debuglet failed; the executor log has the details"

// hostFailure is what the runtime returns when a host function fails with a Go
// runtime error: wazero's wrapper around the panic, carrying the wasm and the
// Go stack traces, inside the runtime's own prefix.
func hostFailure() error {
	return fmt.Errorf("failed to instantiate module: %w", fmt.Errorf("%w (recovered by wazero)\nwasm stack trace:\n\tenv.receive_data(i32,i32,i32) i32\n\n%s\ngoroutine 7 [running]:\n/srv/executor/build/internal/executor/debuglet/wasm/host_functions.go:275 token=SENTINEL-TOKEN",
		errors.New("receive_data: read error: read tcp 10.0.0.5:41234->192.0.2.1:80: i/o timeout"), "Go runtime stack trace:"))
}

// ranRuntime wraps err the way a failed guest execution reaches the outcome.
func ranRuntime(err error) error {
	return fmt.Errorf("failed to run debuglet: %w", fmt.Errorf("failed to instantiate module: %w", err))
}

// refusedHostCall wraps a policy refusal the way wazero returns a host
// function that panicked with it.
func refusedHostCall(refusal error) error {
	return ranRuntime(fmt.Errorf("module[] function[_start] failed: %w", fmt.Errorf("%w (recovered by wazero)\nwasm stack trace:\n\tenv.connect_tcp(i32,i32,i32) i32", fmt.Errorf("connect: %w", refusal))))
}

// uncompiled wraps a compile failure the way module setup returns it.
func uncompiled(detail string) error {
	return fmt.Errorf("failed to initialize debuglet: %w", fmt.Errorf("failed to initialize debuglet runtime: %w",
		fmt.Errorf("createWASMInstance: %w", &debuglet.CompileError{Err: errors.New(detail)})))
}

func TestPublicOutcomeClassification(t *testing.T) {
	longDetail := strings.Repeat("section 2: import name ", 20)
	// The two-byte rune starts at byte 255 of the public text, so a byte cut at
	// 256 would split it.
	splitDetail := strings.Repeat("x", 230) + "é" + strings.Repeat("y", 100)
	cases := []struct {
		name    string
		outcome error
		want    string
		absent  []string
	}{
		{"abort reason", abortReason{reason: "cancelled via API"}, "cancelled via API", nil},
		{"abort reason after the guest stopped", ranRuntime(fmt.Errorf("debuglet execution canceled: %w", abortReason{reason: "cancelled via API"})), "cancelled via API", nil},
		{"control characters in an abort reason", abortReason{reason: "cancelled\tby\x00operator\nnow"}, "cancelled by operator now", nil},
		{"invalid UTF-8 in an abort reason", abortReason{reason: "bad \xff reason"}, "bad \uFFFD reason", nil},
		{"policy timeout", policyTimeout{budget: 30 * time.Second}, "timeout of 30s exceeded", nil},
		{"policy timeout joined with a close failure", fmt.Errorf("failed to run debuglet: %w", errors.Join(policyTimeout{budget: 30 * time.Second}, errors.New("close tcp 10.0.0.5:41234: use of closed network connection"))),
			"timeout of 30s exceeded", []string{"10.0.0.5"}},
		{"guest exit code", ranRuntime(sys.NewExitError(7)), "debuglet exited with code 7", nil},
		{"guest exit code is unsigned", ranRuntime(sys.NewExitError(0x80000000)), "debuglet exited with code 2147483648", nil},
		{"context cancellation exit code is no guest exit", ranRuntime(sys.NewExitError(sys.ExitCodeContextCanceled)), "debuglet cancelled", nil},
		{"deadline exit code is no guest exit", ranRuntime(sys.NewExitError(sys.ExitCodeDeadlineExceeded)), genericOutcome, nil},
		{"operator denial", refusedHostCall(fmt.Errorf("%w: 10.0.0.1 is in the denied range 10.0.0.0/8", netpolicy.ErrDenied)),
			"destination refused: denied by the operator network policy", []string{"10.0.0.0/8", "10.0.0.1", "wasm stack trace", "connect"}},
		{"undeclared destination", refusedHostCall(fmt.Errorf("%w: 203.0.113.9", netpolicy.ErrNotInPolicy)),
			"destination refused: outside the job's destination policy", []string{"203.0.113.9"}},
		{"unavailable transport", refusedHostCall(fmt.Errorf("%w: icmp is disabled by the operator network policy", netpolicy.ErrTransportUnavailable)),
			"destination refused: transport unavailable", []string{"icmp"}},
		{"module that does not compile", uncompiled("invalid magic number"), "module does not compile: invalid magic number", nil},
		{"long compile detail", uncompiled(longDetail), ("module does not compile: " + longDetail)[:256] + "...", nil},
		{"compile detail cut on a rune boundary", uncompiled(splitDetail), "module does not compile: " + strings.Repeat("x", 230) + "...", nil},
		{"cancellation", context.Canceled, "debuglet cancelled", nil},
		{"cancellation during allocation", fmt.Errorf("failed to allocate debuglet: %w", context.Canceled), "debuglet cancelled", nil},
		{"host function failure", ranRuntime(hostFailure()), genericOutcome,
			[]string{"/srv/executor", "10.0.0.5", "SENTINEL-TOKEN", "wasm stack trace", "recovered by wazero", "\n"}},
		{"trap", ranRuntime(fmt.Errorf("module[] function[_start] failed: %w", errors.New("wasm error: unreachable\nwasm stack trace:\n\t.main()"))), genericOutcome, nil},
		{"dispatcher transport failure", fmt.Errorf("failed to allocate debuglet: %w", fmt.Errorf("failed to allocate on dispatcher: %w", status.Error(codes.Unknown, "check debuglet payment: sql: database is closed"))),
			genericOutcome, []string{"sql"}},
		{"listener address", fmt.Errorf("failed to initialize debuglet: %w", fmt.Errorf("failed to start listener: %w", errors.New("startServers: failed to start TCP listener: listen tcp 203.0.113.5:4000: bind: address already in use"))),
			genericOutcome, []string{"203.0.113.5"}},
		{"operator configuration", fmt.Errorf("failed to register debuglet: %w", fmt.Errorf("invalid operator network policy: %w", errors.New(`network.policy.denied_destinations: "x" is not a CIDR block`))),
			genericOutcome, []string{"denied_destinations"}},
		{"start marker", scheduler.ErrDebugletAlreadyStarted, genericOutcome, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := publicOutcome(tc.outcome)
			if got != tc.want {
				t.Fatalf("public outcome %q, want %q", got, tc.want)
			}
			if len(got) > 256+len("...") || !utf8.ValidString(got) || strings.ContainsAny(got, "\r\n") {
				t.Fatalf("public outcome is not one bounded line: %q", got)
			}
			for _, detail := range tc.absent {
				if strings.Contains(got, detail) {
					t.Fatalf("public outcome %q carries %q", got, detail)
				}
			}
		})
	}
}

// A failed run reports its classified result to the dispatcher, while the
// executor log keeps the whole outcome under the run ID.
func TestPublicOutcomeOfFailedRuns(t *testing.T) {
	t.Run("host failure", func(t *testing.T) {
		peer := newOperationPeer()
		e, _ := newExecutorRPCFixture(t, peer, nil)
		core, logs := observer.New(zapcore.ErrorLevel)
		e.logger = zap.New(core)
		spec := operationSpec()
		installOperationRuntime(e, spec, &operationRuntime{run: func(context.Context, chan<- []byte) error { return hostFailure() }})
		call := startOperationTest(t, e, spec)
		if !operationAwait(t, call.done, "failed run") {
			return
		}
		if report := operationReport(t, peer, spec.DebugletID); report.ExitCode != -1 || report.GetErrorMessage() != genericOutcome {
			t.Fatalf("host failure reported exit %d %q, want -1 and only %q", report.ExitCode, report.GetErrorMessage(), genericOutcome)
		}
		entries := logs.FilterMessage("Debuglet handler failed").All()
		if len(entries) != 1 {
			t.Fatalf("executor logged %d handler failures, want 1", len(entries))
		}
		if fields := entries[0].ContextMap(); fields["debugletID"] != spec.DebugletID.String() || !strings.Contains(fmt.Sprint(fields["error"]), "token=SENTINEL-TOKEN") {
			t.Fatalf("executor log lost the full outcome: %v", fields)
		}
	})

	t.Run("policy timeout", func(t *testing.T) {
		peer := newOperationPeer()
		e, _ := newExecutorRPCFixture(t, peer, nil)
		spec := operationSpec()
		spec.Policy.Timeout = 50 * time.Millisecond
		installOperationRuntime(e, spec, &operationRuntime{run: func(ctx context.Context, _ chan<- []byte) error {
			<-ctx.Done()
			return context.Cause(ctx)
		}})
		call := startOperationTest(t, e, spec)
		if !operationAwait(t, call.done, "timed out run") {
			return
		}
		if report := operationReport(t, peer, spec.DebugletID); report.ExitCode != -1 || report.GetErrorMessage() != "timeout of 50ms exceeded" {
			t.Fatalf("policy timeout reported exit %d %q", report.ExitCode, report.GetErrorMessage())
		}
	})

	t.Run("module that does not compile", func(t *testing.T) {
		peer := newOperationPeer()
		e, _ := newExecutorRPCFixture(t, peer, nil)
		spec := operationSpec()
		spec.Wasm = []byte("not a module")
		call := startOperationTest(t, e, spec)
		if !operationAwait(t, call.done, "rejected module") {
			return
		}
		if report := operationReport(t, peer, spec.DebugletID); report.ExitCode != -1 || report.GetErrorMessage() != "module does not compile: invalid magic number" {
			t.Fatalf("rejected module reported exit %d %q", report.ExitCode, report.GetErrorMessage())
		}
	})
}
