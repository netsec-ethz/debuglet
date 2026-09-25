//go:build linux || darwin

package demo

import (
	"path/filepath"
	"testing"

	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/readiness"
)

// TestGeneratedConfigurationsLoad keeps the configurations this package writes
// for its services loadable by the daemons that read them.
func TestGeneratedConfigurationsLoad(t *testing.T) {
	dir := t.TempDir()
	dispatcherPath := filepath.Join(dir, "dispatcher.toml")
	if err := writeConfig(dispatcherPath, dispatcherConfiguration("test-version", filepath.Join(dir, "dispatcher.sqlite"))); err != nil {
		t.Fatalf("write dispatcher configuration: %v", err)
	}
	dispatcher, err := dispatcherconfig.LoadConfig(dispatcherPath)
	if err != nil {
		t.Fatalf("generated dispatcher configuration: %v", err)
	}
	if dispatcher.Server.HTTPPort != 0 || dispatcher.Server.GRPCPort != 0 || !dispatcher.Sui.Disabled {
		t.Fatalf("unexpected dispatcher configuration: %+v", dispatcher)
	}
	// The local development profile of the HTTP API is an explicit opt-in, and
	// this is the one place that asks for it: dbl demo and dbl up submit
	// without a credential and depend on it.
	if !dispatcher.Server.LocalDevelopment || dispatcher.Server.BehindTLSTerminator {
		t.Fatalf("generated local configuration does not ask for the local development profile alone: %+v", dispatcher.Server)
	}

	record := readiness.Record{GRPCAddr: "127.0.0.1:9001", HTTPAddr: "127.0.0.1:9000"}
	// Combined environments size the chain explicitly; a role derives it.
	for name, chainLength := range map[string]any{"combined": int64(3600), "role": 0} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "executor.toml")
			config := executorConfiguration("test-version", "84b8f75e-a779-465a-8ce3-54b04ac15ef2", filepath.Join(dir, "executor.sqlite"), record)
			config["tesla"].(map[string]any)["chain_length"] = chainLength
			if err := writeConfig(path, config); err != nil {
				t.Fatalf("write executor configuration: %v", err)
			}
			executor, err := executorconfig.LoadConfig(path)
			if err != nil {
				t.Fatalf("generated executor configuration: %v", err)
			}
			if executor.Network.PacketCounter != "fallback" || executor.Dispatcher.Addr != record.GRPCAddr {
				t.Fatalf("unexpected executor configuration: %+v", executor)
			}
		})
	}
}
