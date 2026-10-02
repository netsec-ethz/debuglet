// Package daemonlog holds the logger and shutdown handling the dispatcher and
// executor daemons share, so both report the same way.
package daemonlog

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

// New builds a daemon logger that writes to stdout without stack traces. It
// uses zap's development encoding, or its JSON production encoding when
// jsonLogs is set. A level zap cannot parse falls back to info; the daemons'
// configuration loaders reject such a level before this is reached.
func New(level string, jsonLogs bool) *zap.Logger {
	logLevel, err := zap.ParseAtomicLevel(level)
	if err != nil {
		logLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logCfg := zap.NewDevelopmentConfig()
	if jsonLogs {
		logCfg = zap.NewProductionConfig()
	}
	logCfg.Level = logLevel
	logCfg.OutputPaths = []string{"stdout"}
	logCfg.DisableStacktrace = true
	logger, _ := logCfg.Build()
	return logger
}

// Run calls run with a context that SIGINT or SIGTERM cancels. When a signal
// arrives it logs, once and tagged with role, that shutdown was requested, and
// it returns only after that notice is written, so the notice always precedes
// whatever the caller logs about how the daemon stopped.
func Run(logger *zap.Logger, role string, run func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	requested := make(chan struct{})
	stopNotice := context.AfterFunc(ctx, func() {
		defer close(requested)
		logger.Info("Shutdown requested; stopping and joining local work", zap.String("role", role))
	})
	err := run(ctx)
	// Cancellation may precede the callback starting; stopping it then would
	// discard the shutdown notice the completed run is waiting for.
	if ctx.Err() != nil || !stopNotice() {
		<-requested
	}
	return err
}
