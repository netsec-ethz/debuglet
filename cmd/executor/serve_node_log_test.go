// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
)

func TestExecutorLostControlSessionLogsReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	core, logs := observer.New(zap.InfoLevel)
	lost := errors.New("connection lost")
	stopRetrying := errors.New("stop retrying")
	sessions, waits := 0, 0
	err := serveNode(ctx, "", "lost-test", nodeServices{
		newSession: func() (executorSession, error) {
			sessions++
			s := newCommandSession()
			s.Stop(&controlsession.EndError{Kind: controlsession.TransportUnavailable, Err: lost})
			return s, nil
		},
		wait: func(context.Context, time.Duration) error {
			waits++
			if waits == 2 {
				return stopRetrying
			}
			return nil
		},
		closeNode: func() error { return nil }, closeStorage: func() error { return nil },
		logger: zap.New(core),
	})
	if !errors.Is(err, stopRetrying) || sessions != 2 || waits != 2 {
		t.Fatalf("result=%v sessions=%d waits=%d", err, sessions, waits)
	}
	entries := logs.FilterMessage("Control session lost; reconnecting").All()
	if len(entries) != 2 {
		t.Fatalf("reconnect lines: %d of %d entries", len(entries), logs.Len())
	}
	for i, delay := range []time.Duration{250 * time.Millisecond, 500 * time.Millisecond} {
		entry, fields := entries[i], entries[i].ContextMap()
		if entry.Level != zapcore.WarnLevel || fields["max_delay"] != delay || fields["executor_id"] != "lost-test" {
			t.Fatalf("line %d: level=%v fields=%v", i, entry.Level, fields)
		}
		if cause, _ := fields["error"].(string); !strings.Contains(cause, lost.Error()) {
			t.Fatalf("line %d without cause: %v", i, fields)
		}
	}
}

func TestExecutorParentStopLogsNoReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	core, logs := observer.New(zap.DebugLevel)
	sessions := 0
	err := serveNode(ctx, "", "stop-test", nodeServices{
		newSession: func() (executorSession, error) {
			sessions++
			cancel()
			return newCommandSession(), nil
		},
		wait:      func(context.Context, time.Duration) error { t.Error("retry after parent stop"); return nil },
		closeNode: func() error { return nil }, closeStorage: func() error { return nil },
		logger: zap.New(core),
	})
	if err != nil || sessions != 1 {
		t.Fatalf("result=%v sessions=%d", err, sessions)
	}
	if n := logs.FilterMessage("Control session lost; reconnecting").Len(); n != 0 {
		t.Fatalf("reconnect lines after parent stop: %d", n)
	}
}
