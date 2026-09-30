// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/buildinfo"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"

	"github.com/netsec-ethz/debuglet/internal/executor"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"

	scionFlag "github.com/scionproto/scion/private/app/flag"
)

func main() {
	version := flag.Bool("version", false, "Print build identity as JSON and exit")
	cfgPath := flag.String("config", "/etc/debuglet/executor/executor.toml", "Path to executor configuration file")
	readyFile := flag.String("ready-file", "", "Publish startup record at an absent path in an owned private directory")
	initDatabase := flag.String("init-database", "", "Create a new database at this path, then exit; its parent must be a private directory owned by this user")
	upgrade := flag.Bool("upgrade-database", false, "Apply the packaged migrations to the configured database, then exit. Stop the daemon and back the file up first")
	checkDatabase := flag.Bool("check-database", false, "Report whether the configured database is supported by this build, then exit; exit status 3 means it needs the upgrade, 4 that the upgrade drops recorded data")
	acceptDataLoss := flag.Bool("accept-data-loss", false, "With -upgrade-database, apply a migration that drops the recorded runs and their logs")
	flag.Parse()
	initRequested, initOnly := false, true
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "init-database" {
			initRequested = true
		} else {
			initOnly = false
		}
	})
	if initRequested {
		if !initOnly || flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "executor: -init-database cannot be combined with other flags or arguments")
			os.Exit(1)
		}
		if err := storagecheck.BootstrapFresh(context.Background(), storagecheck.Executor, *initDatabase); err != nil {
			fmt.Fprintf(os.Stderr, "executor: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("created executor database %s\n", absoluteDatabasePath(*initDatabase))
		return
	}
	if *version {
		modified := false
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.modified" {
					modified = setting.Value == "true"
				}
			}
		}
		fmt.Printf("{\"module\":%q,\"version\":%q,\"revision\":%q,\"modified\":%t}\n", "github.com/netsec-ethz/debuglet", buildinfo.Version, buildinfo.Revision, modified)
		return
	}

	if *checkDatabase && (*upgrade || *acceptDataLoss) {
		fmt.Fprintln(os.Stderr, "executor: -check-database cannot be combined with another administration flag")
		os.Exit(1)
	}
	if *acceptDataLoss && !*upgrade {
		fmt.Fprintln(os.Stderr, "executor: -accept-data-loss is only valid with -upgrade-database")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "executor: %v\n", err)
		os.Exit(1)
	}

	// Checking a database only reads it, so it is safe while the daemon
	// serves it; the answer tells an upgrade whether there is work to do.
	if *checkDatabase {
		err := storagecheck.Check(context.Background(), storagecheck.Executor, cfg.Database.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "executor: %v\n", err)
			os.Exit(checkDatabaseStatus(err))
		}
		fmt.Printf("executor database %s is current for this build\n", absoluteDatabasePath(cfg.Database.Path))
		return
	}
	// A database is upgraded only when its operator asks for it, never at
	// start: a normal start refuses an outdated schema instead.
	if *upgrade {
		options := []storagecheck.UpgradeOption{storagecheck.ReportRecovery(printRecovery("executor"))}
		if *acceptDataLoss {
			options = append(options, storagecheck.AcceptDataLoss())
		}
		path := absoluteDatabasePath(cfg.Database.Path)
		fmt.Printf("upgrading executor database %s\n", path)
		version, err := storagecheck.Upgrade(context.Background(), storagecheck.Executor, cfg.Database.Path, options...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "executor: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("database %s now records executor schema version %d\n", path, version)
		// The daemon enforces foreign keys on new writes only; rows an
		// earlier version wrote without them are reported, not changed.
		violations, err := storagecheck.ForeignKeyViolations(context.Background(), cfg.Database.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "executor: %v\n", err)
			os.Exit(1)
		}
		for _, violation := range violations {
			fmt.Fprintf(os.Stderr, "executor: warning: %s; the daemon keeps them, but they are not consistent\n", violation)
		}
		return
	}

	logger := daemonlog.New(cfg.Logging.LogLevel, cfg.Logging.JSONLogs)
	defer logger.Sync()

	err = daemonlog.Run(logger, "executor", func(ctx context.Context) error {
		return runExecutor(ctx, cfg, *readyFile, logger)
	})
	if err != nil {
		logger.Error("executor exited with error", zap.Error(err))
		logger.Sync()
		os.Exit(1)
	}
	logger.Info("Executor stopped", zap.String("role", "executor"), zap.Bool("joined", true))
}

// checkDatabaseStatus maps the answer of -check-database to its exit status:
// 3 for a database the upgrade brings to this build keeping its data, 4 for
// one whose upgrade drops the recorded runs, 1 for any other refusal.
func checkDatabaseStatus(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, storagecheck.ErrOutdated) && errors.Is(err, storagecheck.ErrDataLoss):
		return 4
	case errors.Is(err, storagecheck.ErrOutdated):
		return 3
	default:
		return 1
	}
}

// absoluteDatabasePath names the database file an administration mode acts
// on, which is not always next to the configuration file that names it.
func absoluteDatabasePath(path string) string {
	if path == "" {
		return path
	}
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return path
}

// logRecovery warns once that SQLite rolled back the unfinished transaction a
// process killed mid-write left in the database's journal.
func logRecovery(logger *zap.Logger) func(storagecheck.Recovery) {
	return func(r storagecheck.Recovery) {
		logger.Warn("Database crash recovery ran: SQLite rolled back the unfinished transaction a stopped process left in the journal; the database holds its last committed state",
			zap.String("database", r.Path), zap.String("journal", r.Journal))
	}
}

// printRecovery is logRecovery for an administration mode, which reports on
// standard error.
func printRecovery(role string) func(storagecheck.Recovery) {
	return func(r storagecheck.Recovery) {
		fmt.Fprintf(os.Stderr, "%s: warning: database crash recovery ran: SQLite rolled back the unfinished transaction in journal %s; database %s holds its last committed state\n",
			role, r.Journal, r.Path)
	}
}

// configureSCIONEnvironment loads the SCION daemon address unless the operator
// disabled it, in which case neither the load nor the variable it sets happens.
// It isolates this process's configuration and decides no traffic policy.
func configureSCIONEnvironment(disabled bool, load func() (string, error), set func(string, string) error) error {
	if disabled {
		return nil
	}
	address, err := load()
	if err != nil {
		return fmt.Errorf("load SCION environment: %w", err)
	}
	return set("SCION_DAEMON_ADDRESS", address)
}

func runExecutor(ctx context.Context, cfg *config.ExecutorConfig, readyFile string, logger *zap.Logger) error {
	if err := configureSCIONEnvironment(cfg.Network.DisableSCIONEnvironment, func() (string, error) {
		var flags scionFlag.SCIONEnvironment
		err := flags.LoadExternalVars()
		return flags.Daemon(), err
	}, os.Setenv); err != nil {
		return err
	}
	// Refuse an unsupported schema before opening the database, constructing
	// the node's resources or restoring queued work.
	if err := storagecheck.CheckAtStart(ctx, storagecheck.Executor, cfg.Database.Path, logRecovery(logger)); err != nil {
		return err
	}
	db, err := sqlitedb.Open(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	node, err := executor.NewNode(cfg, logger, db)
	if err != nil {
		return errors.Join(err, db.Close())
	}
	return serveNode(ctx, readyFile, cfg.Identity.ExecutorID, nodeServices{
		newSession: func() (executorSession, error) { return executor.NewSession(node, db) },
		closeNode:  node.Close, closeStorage: db.Close,
		wait: waitReconnect, logger: logger,
	})
}

type executorSession interface {
	Run(context.Context) error
	Stop(error)
	Wait(context.Context) error
	WaitResourcesReady(context.Context) error
	Lost() <-chan struct{}
	Cause() error
}

type nodeServices struct {
	newSession              func() (executorSession, error)
	closeNode, closeStorage func() error
	wait                    func(context.Context, time.Duration) error
	logger                  *zap.Logger // nil logs nothing
}

func waitReconnect(ctx context.Context, maximum time.Duration) error {
	// Half-to-full jitter bounds repeated failures without synchronized retries.
	delay := maximum/2 + time.Duration(rand.Int64N(int64(maximum-maximum/2)+1))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func serveNode(ctx context.Context, readyFile, executorID string, services nodeServices) (result error) {
	logger := services.logger
	if logger == nil {
		logger = zap.NewNop()
	}
	clean := true
	defer func() {
		if !clean {
			return
		} // Retain shared resources until the process-exit boundary.
		if err := services.closeNode(); err != nil {
			result = errors.Join(result, fmt.Errorf("close node: %w", err))
			return
		}
		result = errors.Join(result, services.closeStorage())
	}()
	backoff := 250 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return nil
		}
		session, err := services.newSession()
		if err != nil {
			return fmt.Errorf("create executor session: %w", err)
		}
		clean = false
		end, joined, healthy := serveSession(ctx, readyFile, executorID, session)
		if joined != nil {
			return errors.Join(end, fmt.Errorf("shutdown session (shared resources retained): %w", joined))
		}
		clean = true
		var typed *controlsession.EndError
		typedEnd := errors.As(end, &typed)
		// Fatal local cleanup/compatibility failures remain visible even when
		// a concurrent parent stop otherwise makes network loss an ordinary exit.
		if typedEnd && (typed.Kind == controlsession.LocalFailure || typed.Kind == controlsession.IncompatibleProfile) {
			return end
		}
		if ctx.Err() != nil {
			return nil
		}
		if !typedEnd || (typed.Kind != controlsession.TransportUnavailable && typed.Kind != controlsession.LeaseExpired) {
			return end
		}
		if healthy >= 30*time.Second {
			backoff = 250 * time.Millisecond
		}
		logger.Warn("Control session lost; reconnecting", zap.String("executor_id", executorID),
			zap.Error(end), zap.Duration("max_delay", backoff))
		if err := services.wait(ctx, backoff); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		backoff = min(30*time.Second, backoff*2)
	}
}

// serveSession owns and joins the Run caller and the readiness writer as well as
// the transport and scheduler completion Session.Wait reports. A loss signal
// starts cleanup at once and never waits for Run or Listen to return first.
func serveSession(parent context.Context, readyFile, executorID string, session executorSession) (end, cleanupErr error, healthy time.Duration) {
	runDone, readyDone := make(chan struct{}), make(chan struct{})
	readyFailed := make(chan error, 1)
	readyCtx, cancelReady := context.WithCancel(parent)
	defer cancelReady()
	var runErr error
	var readyAt time.Time
	var removalErr error
	go func() { defer close(runDone); runErr = session.Run(parent) }()
	go func() {
		defer close(readyDone)
		if err := session.WaitResourcesReady(readyCtx); err != nil {
			readyFailed <- err
			return
		}
		if readyFile != "" {
			if err := readiness.Write(readyFile, readiness.Record{SchemaVersion: 1, PID: os.Getpid(), ExecutorID: executorID}); err != nil {
				readyFailed <- &controlsession.EndError{Kind: controlsession.LocalFailure, Err: err}
				return
			}
			defer func() {
				if err := os.Remove(readyFile); err != nil {
					removalErr = fmt.Errorf("remove executor readiness: %w", err)
				}
			}()
		}
		readyAt = time.Now()
		<-readyCtx.Done()
	}()
	select {
	case <-session.Lost():
		end = session.Cause()
	case <-parent.Done():
		end = &controlsession.EndError{Kind: controlsession.ParentStopped, Err: context.Cause(parent)}
	case <-runDone:
		end = runErr
	case err := <-readyFailed:
		end = err
		var typed *controlsession.EndError
		if !errors.As(end, &typed) {
			end = &controlsession.EndError{Kind: controlsession.TransportUnavailable, Err: err}
		}
	}
	if parent.Err() != nil {
		end = &controlsession.EndError{Kind: controlsession.ParentStopped, Err: context.Cause(parent)}
	}
	session.Stop(end)
	cancelReady()
	joinCtx, cancelJoin := context.WithTimeout(context.WithoutCancel(parent), scheduler.CleanupTimeout)
	defer cancelJoin()
	cleanupErr = session.Wait(joinCtx)
	// Keep both caller joins explicit even if the Session result reports failure.
	for _, done := range []<-chan struct{}{runDone, readyDone} {
		select {
		case <-done:
		case <-joinCtx.Done():
			cleanupErr = errors.Join(cleanupErr, joinCtx.Err())
			return
		}
	}
	if !readyAt.IsZero() {
		healthy = time.Since(readyAt)
	}
	if cause := session.Cause(); cause != nil {
		end = cause
	}
	if removalErr != nil {
		// Removal failure ends supervisor retry, without relabelling the Bidi
		// first cause or pretending an otherwise joined resource is still live.
		end = &controlsession.EndError{Kind: controlsession.LocalFailure, Err: errors.Join(removalErr, end)}
	} else if end == nil {
		end = &controlsession.EndError{Kind: controlsession.LocalFailure, Err: errors.New("session ended without a cause")}
	}
	return
}
