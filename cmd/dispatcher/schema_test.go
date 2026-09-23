package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"go.uber.org/zap"
)

// TestDispatcherRefusesMissingTLSMaterial checks that certificate files the
// machine does not have end startup before storage or a listener is acquired.
func TestDispatcherRefusesMissingTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	cfg := dispatcherConfig(filepath.Join(dir, "dispatcher.sqlite"))
	cfg.TLS = config.TLSConfig{CertFile: filepath.Join(dir, "absent.crt"), KeyFile: filepath.Join(dir, "absent.key")}
	err := runDispatcher(context.Background(), cfg, filepath.Join(dir, "ready.json"), zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "tls.cert_file") {
		t.Fatalf("absent certificate: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("startup created %v (%v)", entries, err)
	}
}

// TestDispatcherRefusesUnsupportedSchema checks that an unusable database ends
// startup before the dispatcher creates storage, restores the scheduler or
// binds a listener, and that it leaves the state directory alone.
func TestDispatcherRefusesUnsupportedSchema(t *testing.T) {
	t.Run("absent database", func(t *testing.T) {
		dir := t.TempDir()
		err := runDispatcher(context.Background(), dispatcherConfig(filepath.Join(dir, "dispatcher.sqlite")),
			filepath.Join(dir, "ready.json"), zap.NewNop())
		if !errors.Is(err, storagecheck.ErrAbsent) {
			t.Fatalf("absent database: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("startup created %v (%v)", entries, err)
		}
	})
	t.Run("database of another program", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "dispatcher.sqlite")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		ready := filepath.Join(dir, "ready.json")
		if err := runDispatcher(context.Background(), dispatcherConfig(path), ready, zap.NewNop()); !errors.Is(err, storagecheck.ErrUnknown) {
			t.Fatalf("unknown database: %v", err)
		}
		if _, err := os.Lstat(ready); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused startup published readiness: %v", err)
		}
	})
}

func dispatcherConfig(path string) *config.DispatcherConfig {
	return &config.DispatcherConfig{
		Server:    config.ServerConfig{BindHost: "127.0.0.1", Version: "schema-test"},
		Logging:   config.LoggingConfig{LogLevel: "info"},
		Scheduler: config.SchedulerConfig{ExecutorTimeout: 60, SchedulerGranularityMs: 100},
		TLS:       config.TLSConfig{Disable: true},
		Database:  config.DatabaseConfig{Path: path},
		Sui:       config.SuiConfig{Disabled: true},
	}
}
