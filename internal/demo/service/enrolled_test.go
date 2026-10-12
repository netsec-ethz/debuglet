package service

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

func TestEnrolledRequestRequiresCanonicalExecutorState(t *testing.T) {
	f := newFixture(t)
	state := StateDirectory(f.root, storagecheck.Executor, "worker")
	for name, request := range map[string]Request{
		"other directory": {Role: storagecheck.Executor, Name: "worker", EnrolledState: t.TempDir()},
		"dispatcher role": {Role: storagecheck.Dispatcher, Name: "local", EnrolledState: state},
		"grpc override":   {Role: storagecheck.Executor, Name: "worker", EnrolledState: state, DispatcherGRPC: "127.0.0.1:9001"},
		"http override":   {Role: storagecheck.Executor, Name: "worker", EnrolledState: state, DispatcherHTTP: "127.0.0.1:9000"},
	} {
		t.Run(name, func(t *testing.T) {
			request.Root = f.root
			if _, err := Resolve(request, f.assets); err == nil {
				t.Fatal("invalid enrolled request accepted")
			}
		})
	}
}

func TestEnrolledProcessGuard(t *testing.T) {
	for _, tc := range []struct {
		name, identity, database, flag string
		ignore, wantError              bool
	}{
		{name: "same identity", identity: "enrolled-id", flag: "-config", wantError: true},
		{name: "same database", database: "managed", flag: "--config=", wantError: true},
		{name: "relative configuration", identity: "enrolled-id", flag: "relative", wantError: true},
		{name: "unrelated", flag: "-config="},
		{name: "own managed PID", identity: "enrolled-id", flag: "--config", ignore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			p, err := DerivePaths(root, storagecheck.Executor, "worker")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(p.StateDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.DatabasePath, []byte("database"), 0600); err != nil {
				t.Fatal(err)
			}
			database := filepath.Join(root, "other.sqlite")
			if tc.database == "managed" {
				database = p.DatabasePath
			}
			id := tc.identity
			if id == "" {
				id = "other-executor"
			}
			config := filepath.Join(root, "running.toml")
			if err := demo.WriteConfig(config, demo.ExecutorConfiguration(testVersion, id, database, readiness.Record{GRPCAddr: "127.0.0.1:9001", HTTPAddr: "127.0.0.1:9000"})); err != nil {
				t.Fatal(err)
			}
			proc := filepath.Join(root, "proc")
			pid := filepath.Join(proc, "123")
			if err := os.MkdirAll(pid, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/usr/local/bin/debuglet-executor", filepath.Join(pid, "exe")); err != nil {
				t.Fatal(err)
			}
			args := "debuglet-executor\x00" + tc.flag + "\x00" + config + "\x00"
			if strings.HasSuffix(tc.flag, "=") {
				args = "debuglet-executor\x00" + tc.flag + config + "\x00"
			}
			if tc.flag == "relative" {
				if err := os.Symlink(root, filepath.Join(pid, "cwd")); err != nil {
					t.Fatal(err)
				}
				args = "debuglet-executor\x00-config\x00running.toml\x00"
			}
			if err := os.WriteFile(filepath.Join(pid, "cmdline"), []byte(args), 0600); err != nil {
				t.Fatal(err)
			}
			ignored := 0
			if tc.ignore {
				ignored, _ = strconv.Atoi(filepath.Base(pid))
			}
			err = checkEnrolledProcesses(proc, p, "enrolled-id", ignored)
			if (err != nil) != tc.wantError {
				t.Fatalf("guard error = %v, want error %v", err, tc.wantError)
			}
		})
	}
}

func TestRecordedEnrolledUnitCapabilities(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			f := newFixture(t)
			state := StateDirectory(f.root, storagecheck.Executor, "worker")
			p, err := Resolve(Request{Role: storagecheck.Executor, Name: "worker", Root: f.root, EnrolledState: state}, f.assets)
			if err != nil {
				t.Fatal(err)
			}
			p.PacketCapabilities = enabled
			if err := os.MkdirAll(p.StateDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := writeRecord(p); err != nil {
				t.Fatal(err)
			}
			if _, err := f.installer.writeUnit(p); err != nil {
				t.Fatal(err)
			}
			if !enabled {
				data, err := os.ReadFile(RecordPath(f.root, p.Role, p.Name))
				if err != nil || strings.Contains(string(data), "packet_capabilities") {
					t.Fatalf("legacy record has capability field: %s, %v", data, err)
				}
			}
			loaded, _, err := f.installer.load(t.Context(), "stop", p.Role, p.Name)
			if err != nil || loaded.PacketCapabilities != enabled {
				t.Fatalf("record capability changed: %+v, %v", loaded, err)
			}
			if err := f.installer.verifyRemoval(t.Context(), loaded); err != nil {
				t.Fatalf("recorded unit cannot be stopped/removed: %v", err)
			}
		})
	}
}

func TestPacketCapabilitiesExcludeOtherManagedProfiles(t *testing.T) {
	f := newFixture(t)
	for _, role := range []storagecheck.Role{storagecheck.Executor, storagecheck.Dispatcher} {
		p, err := Resolve(Request{Role: role, Name: "local", Root: f.root}, f.assets)
		if err != nil {
			t.Fatal(err)
		}
		// Even a stray record field must not expand a local or dispatcher unit.
		p.PacketCapabilities = true
		if role == storagecheck.Dispatcher {
			p.Enrolled = true
		}
		unit, err := Unit(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(unit, "CapabilityBoundingSet=\nAmbientCapabilities=\n") {
			t.Fatalf("%s unit grants capabilities: %s", role, unit)
		}
	}
}
