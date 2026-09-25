//go:build linux || darwin

package sqlite

import (
	"os"
	"syscall"
	"testing"
)

// The three things an account can put in its own directory in place of the
// file a privileged command expects to find there.
func mustSymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func mustLink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Link(target, path); err != nil {
		t.Fatal(err)
	}
}

func mustPipe(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
}
