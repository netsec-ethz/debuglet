//go:build linux

package demo

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLocalEnvironmentRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	var first LocalEnvironment
	for attempt := 0; attempt < 2; attempt++ {
		f := newSupervisorFixture(t, "success")
		f.dir = dir
		bootstraps := 0
		bootstrap := f.deps.bootstrap
		f.deps.bootstrap = func(ctx context.Context, role SchemaRole, path string) error {
			bootstraps++
			return bootstrap(ctx, role, path)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		readyCalls := 0
		err := up(ctx, f.assets, LocalOptions{StateDir: dir, Port: 0, Ready: func(record LocalEnvironment) error {
			readyCalls++
			if record.State != "ready" || record.Endpoint != f.server.URL || record.StateDir != dir || record.ExecutorID == "" {
				t.Errorf("incorrect readiness: %+v", record)
			}
			data, err := os.ReadFile(filepath.Join(dir, "environment.json"))
			var saved LocalEnvironment
			if err != nil || json.Unmarshal(data, &saved) != nil || saved != record {
				t.Errorf("tool record does not match readiness: %+v, %v", saved, err)
			}
			if attempt == 0 {
				first = record
			} else if record.ExecutorID != first.ExecutorID {
				t.Error("restart changed executor identity")
			}
			cancel()
			return nil
		}}, f.deps, time.Second)
		cancel()
		if err != nil || readyCalls != 1 {
			t.Fatalf("attempt %d: readiness=%d err=%v", attempt, readyCalls, err)
		}
		wantBootstraps := 2
		if attempt == 1 {
			wantBootstraps = 0
		}
		if bootstraps != wantBootstraps {
			t.Fatalf("bootstrap calls %d, want %d", bootstraps, wantBootstraps)
		}
		if !reflect.DeepEqual(f.stops, []string{"executor", "dispatcher"}) {
			t.Fatalf("shutdown order: %v", f.stops)
		}
		for _, child := range f.children {
			if !child.CleanupComplete() {
				t.Fatal("return preceded child cleanup")
			}
		}
		for _, name := range []string{"environment.json", "dispatcher-ready.json", "executor-ready.json"} {
			if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stale ready record %s: %v", name, err)
			}
		}
		for _, name := range []string{"dispatcher.sqlite", "executor.sqlite"} {
			path := filepath.Join(dir, name)
			if attempt == 0 {
				if err := os.WriteFile(path, []byte("retained database bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if data, err := os.ReadFile(path); err != nil || string(data) != "retained database bytes" {
				t.Fatalf("restart altered existing %s: %v", name, err)
			}
		}
	}
}

func TestLocalEnvironmentLockAndVersion(t *testing.T) {
	f := newSupervisorFixture(t, "success")
	dir := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := up(ctx, f.assets, LocalOptions{StateDir: dir, Ready: func(LocalEnvironment) error {
		second := f.deps
		second.startChild = func(ChildSpec) (childProcess, error) {
			t.Error("duplicate start launched child")
			return nil, errors.New("unexpected child")
		}
		if err := up(ctx, f.assets, LocalOptions{StateDir: dir}, second, time.Second); err == nil || !strings.Contains(err.Error(), "already running") {
			t.Errorf("duplicate did not fail at lock: %v", err)
		}
		cancel()
		return nil
	}}, f.deps, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockLocalState(dir)
	if err != nil {
		t.Fatalf("clean shutdown retained lock: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	f.assets.Manifest.Version = "different-version"
	if err := up(context.Background(), f.assets, LocalOptions{StateDir: dir}, f.deps, time.Second); err == nil || !strings.Contains(err.Error(), "new --state-dir") {
		t.Fatalf("changed version accepted databases: %v", err)
	}
	if len(f.children) != 2 {
		t.Fatal("version mismatch launched a child")
	}
}

func TestLocalEnvironmentFailureCleanup(t *testing.T) {
	for _, mode := range []string{"executor startup failure", "early death", "missing readiness", "forced cleanup"} {
		t.Run(mode, func(t *testing.T) {
			f := newSupervisorFixture(t, mode)
			dir := filepath.Join(t.TempDir(), "state")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			ready := false
			startupBudget := time.Second
			if mode == "missing readiness" {
				startupBudget = 100 * time.Millisecond
			}
			err := up(ctx, f.assets, LocalOptions{StateDir: dir, Ready: func(LocalEnvironment) error {
				ready = true
				cancel()
				return nil
			}}, f.deps, startupBudget)
			if err == nil || (mode != "forced cleanup" && ready) {
				t.Fatalf("failure reported success: ready=%t err=%v", ready, err)
			}
			if mode == "missing readiness" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("startup did not honor its separate bound: %v", err)
			}
			if mode == "forced cleanup" && !errors.Is(err, ErrForcedKill) {
				t.Fatalf("signal erased cleanup failure: %v", err)
			}
			for _, child := range f.children {
				if !child.CleanupComplete() {
					t.Fatal("failure returned before fixture child cleanup")
				}
			}
			unlock, err := lockLocalState(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := unlock(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalStateDefaultsAndUnknownDatabase(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "xdg"))
	want := filepath.Join(os.Getenv("XDG_STATE_HOME"), "debuglet")
	if dir, err := DefaultLocalStateDir(); err != nil || dir != want {
		t.Fatalf("XDG state directory: %q %v", dir, err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "executor.sqlite"), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalState(dir, Manifest{Version: "v1"}); err == nil {
		t.Fatal("adopted database without version metadata")
	}
	if localCancellationOnly(errors.Join(context.Canceled, errors.New("cleanup failed"))) {
		t.Fatal("joined cleanup failure classified as normal cancellation")
	}
}
