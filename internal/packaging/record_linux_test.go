//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBuildRecordFIFO(t *testing.T) {
	if path := os.Getenv("DEBUGLET_RECORD_FIFO_TEST"); path != "" {
		if _, err := readBuildRecord(path); err == nil {
			os.Exit(1)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "record")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestBuildRecordFIFO$")
	cmd.Env = append(os.Environ(), "DEBUGLET_RECORD_FIFO_TEST="+path)
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("FIFO validation blocked/failed: %v %s", err, out)
	}
}
