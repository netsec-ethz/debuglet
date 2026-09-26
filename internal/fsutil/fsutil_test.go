// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileReplacesContentsAndMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "record.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new\n" || info.Mode().Perm() != 0o600 {
		t.Fatalf("published %q with mode %v, want %q with 0600", data, info.Mode().Perm(), "new\n")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files remain: %v", entries)
	}
}

func TestWriteFileFailureKeepsThePreviousFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "record.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory at the destination makes the rename fail after the write.
	blocked := filepath.Join(directory, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(blocked, []byte("new"), 0o600); err == nil {
		t.Fatal("publishing over a non-empty directory succeeded")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
		t.Fatalf("unrelated file changed: %q, %v", data, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("a failed publication left temporary files: %v", entries)
	}
}

func TestWriteFileRequiresAnExistingDirectory(t *testing.T) {
	if err := WriteFile(filepath.Join(t.TempDir(), "absent", "record.json"), nil, 0o600); err == nil {
		t.Fatal("publishing into a missing directory succeeded")
	}
}
