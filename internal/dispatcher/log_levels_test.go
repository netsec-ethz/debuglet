// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// newObservedDispatcher opens the registry fixture with a logger that records
// every entry at level or above. The logger is set before any registration,
// so before the expiry worker starts.
func newObservedDispatcher(t *testing.T, level zapcore.Level) (*Dispatcher, *observer.ObservedLogs) {
	t.Helper()
	d, _, _ := newRegistryFixture(t)
	core, logs := observer.New(level)
	d.logger = zap.New(core)
	return d, logs
}

// sessionEnds returns the session-end entries written for reason.
func sessionEnds(logs *observer.ObservedLogs, reason string) []observer.LoggedEntry {
	return logs.Filter(func(e observer.LoggedEntry) bool {
		return e.Message == "Executor control session ended" && e.ContextMap()["reason"] == reason
	}).AllUntimed()
}

// assertSessionEnd checks that entries is one Info entry naming executorID
// and owner's session.
func assertSessionEnd(t *testing.T, entries []observer.LoggedEntry, executorID string, owner *rpc.SessionOwner) {
	t.Helper()
	if len(entries) != 1 {
		t.Fatalf("got %d session-end entries, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if entries[0].Level != zap.InfoLevel || fields["executor_id"] != executorID || fields["session_id"] != owner.Binding().SessionID {
		t.Fatalf("session-end entry: level %s, fields %v", entries[0].Level, fields)
	}
}

// TestHeartbeatEarningsLoggedOnlyAtDebug pins that a heartbeat writes the
// earnings entry only when the logger records Debug entries.
func TestHeartbeatEarningsLoggedOnlyAtDebug(t *testing.T) {
	for _, tc := range []struct {
		level zapcore.Level
		want  int
	}{
		{zap.InfoLevel, 0},
		{zap.DebugLevel, 1},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			d, logs := newObservedDispatcher(t, tc.level)
			registryRegister(t, d, "earnings")
			mutation := effectTestMutation(t, d, "earnings")
			_, err := d.OnHeartbeat(context.Background(), mutation, &pb.HeartbeatRequest{ExecutorId: "earnings", TimestampNs: 1})
			mutation.Finish()
			if err != nil {
				t.Fatal(err)
			}
			if got := logs.FilterMessage("Earnings").Len(); got != tc.want {
				t.Fatalf("heartbeat at %s wrote %d earnings entries, want %d", tc.level, got, tc.want)
			}
		})
	}
}

// TestExecutorDisconnectLogsSessionEnd pins that removing a registered
// executor's session writes one Info entry naming the executor and session,
// and that a disconnect of an owner no longer registered writes none. A
// registration that replaces a live owner writes one entry for the replaced
// session.
func TestExecutorDisconnectLogsSessionEnd(t *testing.T) {
	d, logs := newObservedDispatcher(t, zap.InfoLevel)
	stale := registryRegister(t, d, "session")
	if got := len(sessionEnds(logs, "replaced")); got != 0 {
		t.Fatalf("first registration wrote %d replacement entries, want 0", got)
	}
	current := registryRegister(t, d, "session")
	assertSessionEnd(t, sessionEnds(logs, "replaced"), "session", stale)

	d.OnExecutorDisconnected(stale)
	if got := len(sessionEnds(logs, "transport closed")); got != 0 {
		t.Fatalf("disconnect of a replaced owner wrote %d session-end entries, want 0", got)
	}

	d.OnExecutorDisconnected(current)
	assertSessionEnd(t, sessionEnds(logs, "transport closed"), "session", current)
	if _, ok := d.GetExecutor("session"); ok {
		t.Fatal("registered owner's disconnect left the executor registered")
	}
}

// TestLeaseExpiryLogsSessionEnd pins that retiring an owner whose lease ran
// out writes one Info entry naming the executor and session, and that the
// transport's later disconnect of that owner writes none.
func TestLeaseExpiryLogsSessionEnd(t *testing.T) {
	d, logs := newObservedDispatcher(t, zap.InfoLevel)
	var clock atomic.Int64
	base := time.Unix(1700000000, 0)
	clock.Store(base.UnixNano())
	d.now = func() time.Time { return time.Unix(0, clock.Load()) }
	owner := registryRegister(t, d, "lease")
	clock.Store(base.Add(d.ControlLeaseDuration()).UnixNano())
	if !d.expireOwner(owner) {
		t.Fatal("owner at its lease deadline was not retired")
	}
	assertSessionEnd(t, sessionEnds(logs, "lease expired"), "lease", owner)
	d.OnExecutorDisconnected(owner)
	if got := len(sessionEnds(logs, "transport closed")); got != 0 {
		t.Fatalf("disconnect after expiry wrote %d session-end entries, want 0", got)
	}
}
