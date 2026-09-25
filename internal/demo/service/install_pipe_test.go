//go:build linux || darwin

package service

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
)

// A named pipe answers an open only when somebody opens the other end. The
// account owns the state directory between installations, so leaving one there
// would stop the next install indefinitely if it opened what it found the
// ordinary way. Opening never waits, and what the entry is is then read from
// the descriptor rather than from the directory entry.
func TestOwnershipNeverWaitsOnANamedPipe(t *testing.T) {
	f := newFixture(t)
	installer, err := New(Options{
		Root: f.root, Manager: f.manager, ReadyTimeout: 2 * time.Second, StopTimeout: time.Second,
		// The real fchown and fchmod, with an account this test may apply.
		LookupAccount: func(string, string) (Account, error) {
			return Account{UID: os.Getuid(), GID: os.Getgid()}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.installer = installer
	if _, err := f.install(demo.ExecutorSchema, "worker", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	pipe := filepath.Join(StateDirectory(f.root, demo.ExecutorSchema, "worker"), "pipe")
	if err := syscall.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.install(demo.ExecutorSchema, "worker", false)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a named pipe was handed to the service account")
		}
		if !strings.Contains(err.Error(), pipe) {
			t.Fatalf("the refusal does not name the entry: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the install is waiting for somebody to open the other end of the pipe")
	}
}
