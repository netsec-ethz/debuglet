package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

func TestInitializeDatabaseCommand(t *testing.T) {
	if os.Getenv("DEBUGLET_INIT_COMMAND_TEST") == "dispatcher" {
		index := slices.Index(os.Args, "--")
		os.Args = append([]string{os.Args[0]}, os.Args[index+1:]...)
		flag.CommandLine = flag.NewFlagSet("dispatcher", flag.ExitOnError)
		main()
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(wantSuccess bool, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, append([]string{"-test.run=^TestInitializeDatabaseCommand$", "--"}, args...)...)
		command.Env = append(os.Environ(), "DEBUGLET_INIT_COMMAND_TEST=dispatcher")
		output, err := command.CombinedOutput()
		if (err == nil) != wantSuccess {
			t.Fatalf("%v: %v\n%s", args, err, output)
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "dispatcher.sqlite")
	for _, extra := range [][]string{{"-upgrade-database"}, {"-check-database"}, {"-accept-data-loss"}, {"-config", "unused"}, {"-ready-file", "unused"}, {"-grant-operator", "unused"}, {"-revoke-operator", "unused"}, {"-enroll-executor", "unused"}, {"-revoke-executor", "unused"}, {"unexpected"}} {
		run(false, append([]string{"-init-database", path}, extra...)...)
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refused arguments created database: %v", err)
		}
	}
	run(false, "-init-database", "")
	run(true, "-init-database", path)
	if err := storagecheck.Check(t.Context(), storagecheck.Dispatcher, path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("new database mode: %v, %v", info, err)
	}
	run(false, "-init-database", path)
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("refused existing database changed: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".sqlite") {
		t.Fatalf("initialization left companion files: %v, %v", entries, err)
	}
}
