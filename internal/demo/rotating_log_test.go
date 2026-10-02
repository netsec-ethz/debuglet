//go:build linux

package demo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDaemonLogRotationAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executor.log")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	options := LogOptions{MaxBytes: 32, Files: 3, MaxAge: time.Hour}
	for attempt := 0; attempt < 3; attempt++ {
		log, err := newRotatingLog(path, options, cancel)
		if err != nil {
			t.Fatal(err)
		}
		// One write larger than the entire retained allowance must still
		// complete and leave the newest diagnostics available.
		if n, err := log.Write(bytes.Repeat([]byte{byte('a' + attempt)}, 1024)); n != 1024 || err != nil {
			t.Fatalf("write: %d, %v", n, err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		files, err := filepath.Glob(path + "*")
		if err != nil || len(files) != 3 {
			t.Fatalf("files: %v, %v", files, err)
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil || len(data) != 32 || !bytes.Equal(data, bytes.Repeat([]byte{byte('a' + attempt)}, 32)) {
				t.Fatalf("retained %s: %q, %v", file, data, err)
			}
		}
	}
	if ctx.Err() != nil {
		t.Fatalf("rotation stopped role: %v", context.Cause(ctx))
	}
}

func TestDaemonLogRotationKeepsDescriptors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "executor.log")
	if err := os.WriteFile(filepath.Join(dir, "unrelated"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	openFiles := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	log, err := newRotatingLog(path, LogOptions{MaxBytes: 8, Files: 3, MaxAge: time.Hour}, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	// The first rotation warms any lazily opened runtime descriptors, so the
	// baseline holds only the root and the live file.
	if _, err := log.Write(bytes.Repeat([]byte{'w'}, 16)); err != nil {
		t.Fatal(err)
	}
	before := openFiles()
	for rotation := 0; rotation < 500; rotation++ {
		if n, err := log.Write(bytes.Repeat([]byte{byte('a' + rotation%26)}, 8)); n != 8 || err != nil {
			t.Fatalf("rotation %d: %d, %v", rotation, n, err)
		}
	}
	if after := openFiles(); after > before+2 {
		t.Fatalf("rotation leaked descriptors: %d before, %d after", before, after)
	}
	if _, err := io.WriteString(log, "live"); err != nil || ctx.Err() != nil {
		t.Fatalf("live writer lost: %v, %v", err, context.Cause(ctx))
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "live" {
		t.Fatalf("live file: %q, %v", got, err)
	}
	files, err := filepath.Glob(path + "*")
	if err != nil || len(files) != 3 {
		t.Fatalf("retained files: %v, %v", files, err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "unrelated")); err != nil || string(got) != "keep" {
		t.Fatalf("unrelated state changed: %q, %v", got, err)
	}
}

func TestDaemonLogRetentionChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dispatcher.log")
	for name, data := range map[string]string{"dispatcher.log": "oldest-latest", "dispatcher.log.1": "expired", "dispatcher.log.2": "excess", "unrelated": "keep"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path+".1", past, past); err != nil {
		t.Fatal(err)
	}
	log, err := newRotatingLog(path, LogOptions{MaxBytes: 6, Files: 2, MaxAge: time.Hour}, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if got, err := os.ReadFile(path); err != nil || string(got) != "latest" {
		t.Fatalf("smaller cap did not keep latest diagnostics: %q, %v", got, err)
	}
	for _, name := range []string{path + ".1", path + ".2"} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("out-of-policy archive survived: %s: %v", name, err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(dir, "unrelated")); err != nil || string(got) != "keep" {
		t.Fatalf("unrelated state changed: %q, %v", got, err)
	}
}

func TestDaemonLogRefusesAliases(t *testing.T) {
	for _, suffix := range []string{"", ".1"} {
		for _, link := range []struct {
			name string
			make func(string, string) error
		}{{"symlink", os.Symlink}, {"hardlink", os.Link}} {
			t.Run(suffix+link.name, func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "unrelated")
				path := filepath.Join(dir, "executor.log")
				if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := link.make(target, path+suffix); err != nil {
					t.Fatal(err)
				}
				if log, err := newRotatingLog(path, LogOptions{}, func(error) {}); err == nil {
					log.Close()
					t.Fatal("aliased log was accepted")
				}
				if got, err := os.ReadFile(target); err != nil || string(got) != "keep" {
					t.Fatalf("alias changed target: %q, %v", got, err)
				}
			})
		}
	}
}

func TestLocalLogFailureJoinsChildren(t *testing.T) {
	f := newSupervisorFixture(t, "success")
	f.dir = filepath.Join(t.TempDir(), "state")
	start := f.deps.startChild
	f.deps.startChild = func(spec ChildSpec) (ChildProcess, error) {
		child, err := start(spec)
		if err == nil && spec.Path == f.assets.Executor {
			log := spec.Stdout.(*rotatingLog)
			// Closing a real descriptor exercises the same write-error path
			// as ENOSPC without filling the host filesystem.
			if err := log.file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(log, "cannot persist"); err != nil {
				t.Fatal("failed log must keep draining", err)
			}
		}
		return child, err
	}
	err := up(t.Context(), f.assets, LocalOptions{StateDir: f.dir}, f.deps, time.Second)
	if err == nil || !strings.Contains(err.Error(), "write daemon log") {
		t.Fatalf("log error was hidden: %v", err)
	}
	if len(f.children) != 2 {
		t.Fatalf("started %d children", len(f.children))
	}
	for _, child := range f.children {
		if !child.CleanupComplete() {
			t.Fatal("log failure returned before child joined")
		}
	}
}

func TestDaemonLogExpiredActiveFile(t *testing.T) {
	for _, maxBytes := range []int64{0, 5} {
		t.Run(fmt.Sprintf("max-bytes-%d", maxBytes), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dispatcher.log")
			if err := os.WriteFile(path, []byte("expired"), 0600); err != nil {
				t.Fatal(err)
			}
			past := time.Now().Add(-2 * time.Hour)
			if err := os.Chtimes(path, past, past); err != nil {
				t.Fatal(err)
			}
			log, err := newRotatingLog(path, LogOptions{MaxBytes: maxBytes, MaxAge: time.Hour}, func(error) {})
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			if _, err := io.WriteString(log, "fresh"); err != nil {
				t.Fatal(err)
			}
			files, _ := filepath.Glob(path + "*")
			if len(files) != 1 {
				t.Fatalf("expired file remained: %v", files)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != "fresh" {
				t.Fatalf("active file: %q, %v", got, err)
			}
		})
	}
}

func TestLocalLogRotationKeepsRoleReady(t *testing.T) {
	f := newSupervisorFixture(t, "diagnostic overflow")
	f.dir = filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := false
	options := LocalOptions{StateDir: f.dir, Logs: LogOptions{MaxBytes: 64 << 10, Files: 2}, Ready: func(LocalEnvironment) error {
		ready = true
		cancel()
		return nil
	}}
	if err := up(ctx, f.assets, options, f.deps, time.Second); err != nil || !ready {
		t.Fatalf("noisy local role failed: ready=%v, error=%v", ready, err)
	}
	files, err := filepath.Glob(filepath.Join(f.dir, "executor.log*"))
	if err != nil || len(files) != 2 {
		t.Fatalf("retained files: %v, %v", files, err)
	}
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil || info.Size() > options.Logs.MaxBytes {
			t.Fatalf("retained log exceeds bound: %s, %v", file, err)
		}
	}
	for _, child := range f.children {
		if !child.CleanupComplete() {
			t.Fatal("return preceded child cleanup")
		}
	}
}
