package main

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"go.uber.org/zap"
)

// TestExecutorRefusesUnsupportedSchema checks that an unusable database ends
// startup before the executor opens storage, acquires node resources, joins a
// control session or restores queued work.
func TestExecutorRefusesUnsupportedSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lis, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	t.Run("absent database", func(t *testing.T) {
		dir := t.TempDir()
		err := runExecutor(ctx, executorConfig(lis.Addr().String(), filepath.Join(dir, "executor.sqlite")),
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
		path := filepath.Join(dir, "executor.sqlite")
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
		if err := runExecutor(ctx, executorConfig(lis.Addr().String(), path), ready, zap.NewNop()); !errors.Is(err, storagecheck.ErrUnknown) {
			t.Fatalf("unknown database: %v", err)
		}
		if _, err := os.Lstat(ready); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused startup published readiness: %v", err)
		}
	})

	lis.SetDeadline(time.Now())
	conn, err := lis.Accept()
	if conn != nil {
		conn.Close()
		t.Fatal("network session started on an unusable database")
	}
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("expected no pending connection: %v", err)
	}
}

func executorConfig(dispatcherAddr, path string) *config.ExecutorConfig {
	return &config.ExecutorConfig{
		Identity:   config.IdentityConfig{ExecutorID: "schema-test", Version: "schema-test"},
		Dispatcher: config.DispatcherConfig{Addr: dispatcherAddr, YamuxAddr: dispatcherAddr},
		TLS:        config.TLSConfig{Disable: true},
		Resources:  config.ResourcesConfig{Capacity: 1_000_000_000, MaxDebuglets: 4},
		Tesla:      config.TeslaConfig{Delay: 1, ChainLength: 10},
		Network:    config.NetworkConfig{PacketCounter: "fallback", DisableSCIONEnvironment: true},
		Logging:    config.LoggingConfig{LogLevel: "info"},
		Database:   config.DatabaseConfig{Path: path},
		Pricing:    config.PricingConfig{Currency: "TEST", PricePerBwS: 1},
	}
}
