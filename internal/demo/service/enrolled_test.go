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
