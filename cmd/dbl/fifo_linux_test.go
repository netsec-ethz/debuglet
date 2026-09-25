package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCLICommandsFIFO uses a subprocess so regressing to a blocking FIFO open
// cannot hang the test process. No writer is ever opened. The child executes
// the real main, including signal handling, and creates no child processes.
func TestCLICommandsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guest.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "guest-link.wasm")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"fifo": path, "symlink to fifo": link} {
		t.Run(name, func(t *testing.T) {
			fx := unreachableFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, self, "-test.run=^TestCLIFIFOProcess$", "--",
				"--endpoint", fx.endpoint(), "--timeout", "100ms", "--output", "json",
				"run", "--wasm", path, "--executor", fixExecutor)
			cmd.Env = append(os.Environ(), "DEBUGLET_TEST_FIFO_PROCESS=1")
			cmd.WaitDelay = time.Second
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			// Run waits for and reaps the child on both normal exit and the
			// parent's deadline, whose kill does not depend on CLI cancellation.
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("CLI blocked on FIFO input until the parent deadline: %v; stderr %q", err, stderr.String())
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != exitUsage {
				t.Fatalf("FIFO input: exit %v, want %d; stdout %q, stderr %q", err, exitUsage, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "not a regular file") {
				t.Fatalf("FIFO rejection lacks its reason: stdout %q, stderr %q", stdout.String(), stderr.String())
			}
			if n := fx.total(); n != 0 {
				t.Fatalf("%d requests sent for FIFO input", n)
			}
		})
	}
}

// TestCLIFIFOProcess is selected only by the FIFO subprocess regression.
func TestCLIFIFOProcess(t *testing.T) {
	if os.Getenv("DEBUGLET_TEST_FIFO_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"dbl"}, os.Args[i+1:]...)
			main()
			t.Fatal("main returned without exiting")
		}
	}
	t.Fatal("missing subprocess argument separator")
}
