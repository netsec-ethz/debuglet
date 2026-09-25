// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// exhaustedSchedule returns a chain that ran out an hour ago.
func exhaustedSchedule(t *testing.T) *tesla.KeySchedule {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte("exhausted chain fixture"), ChainLength: 3, Delay: time.Second, Epoch: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// TestUploadRefusedOnExhaustedChain checks that an executor whose key chain has
// run out admits no new run, while the same upload is admitted on a fresh chain.
func TestUploadRefusedOnExhaustedChain(t *testing.T) {
	storage := &uploadBindingScheduler{abortTestScheduler: &abortTestScheduler{}}
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
	ctx, cancel := context.WithTimeout(context.Background(), operationTestBound)
	defer cancel()
	request := boundsUploadRequest()

	if _, err := e.OnUpload(ctx, operationBinding(), request); err != nil {
		t.Fatalf("upload on a fresh chain rejected: %v", err)
	}
	e.teslaSchedule = exhaustedSchedule(t)
	_, err := e.OnUpload(ctx, operationBinding(), request)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("upload on an exhausted chain: %v; want FailedPrecondition", err)
	}
	if len(storage.inserted) != 1 {
		t.Fatalf("uploads reached persistence %d times, want 1", len(storage.inserted))
	}
}

// TestChainReportLogsEachConditionOnce drives the heartbeat's report across
// ticks: each condition produces one line when it is first observed and
// nothing while it holds.
func TestChainReportLogsEachConditionOnce(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte("report fixture"), ChainLength: 180, Delay: time.Minute, Epoch: start})
	if err != nil {
		t.Fatal(err)
	}
	expiry := ks.Expiry()
	var report chainReport
	for _, tick := range []struct {
		name  string
		at    time.Time
		level zapcore.Level
		msg   string
		field string
	}{
		{"fresh", start.Add(time.Minute), zapcore.InfoLevel, "", ""},
		{"nearly", expiry.Add(-30 * time.Minute), zapcore.WarnLevel, "TESLA key chain nearly exhausted", "remaining"},
		{"nearly again", expiry.Add(-time.Minute), zapcore.InfoLevel, "", ""},
		{"exhausted", expiry, zapcore.ErrorLevel, "TESLA key chain exhausted: packets are no longer tagged and new runs are refused; restart the executor or raise tesla.chain_length", "expired_at"},
		{"exhausted again", expiry.Add(time.Hour), zapcore.InfoLevel, "", ""},
	} {
		level, msg, fields := report.observe(ks, tick.at)
		if msg != tick.msg || (msg != "" && level != tick.level) {
			t.Fatalf("%s: observe = (%s, %q); want (%s, %q)", tick.name, level, msg, tick.level, tick.msg)
		}
		if tick.field != "" && (len(fields) == 0 || fields[0].Key != tick.field) {
			t.Fatalf("%s: fields %v do not start with %q", tick.name, fields, tick.field)
		}
	}
}
