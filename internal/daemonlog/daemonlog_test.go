package daemonlog

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewHonoursLevel(t *testing.T) {
	for _, tc := range []struct {
		level string
		want  zapcore.Level
	}{{"debug", zapcore.DebugLevel}, {"warn", zapcore.WarnLevel}, {"not a level", zapcore.InfoLevel}} {
		for _, jsonLogs := range []bool{false, true} {
			logger := New(tc.level, jsonLogs)
			if logger == nil || !logger.Core().Enabled(tc.want) || logger.Core().Enabled(tc.want-1) {
				t.Fatalf("New(%q, %v) does not log at %v", tc.level, jsonLogs, tc.want)
			}
		}
	}
}

func TestRunReturnsWithoutSignalNotice(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	sentinel := errors.New("run failed")
	if err := Run(zap.New(core), "executor", func(context.Context) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Run = %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("unexpected notice: %v", logs.All())
	}
}

func TestRunLogsShutdownRequestBeforeReturning(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	err := Run(zap.New(core), "dispatcher", func(ctx context.Context) error {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	entries := logs.FilterMessage("Shutdown requested; stopping and joining local work").All()
	if len(entries) != 1 || entries[0].ContextMap()["role"] != "dispatcher" {
		t.Fatalf("shutdown notice: %v", logs.All())
	}
}
