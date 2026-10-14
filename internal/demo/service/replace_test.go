// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/internal/testtls"
)

func enrolledReplacementFixture(t *testing.T) (*fixture, Profile, Request) {
	t.Helper()
	f := newFixture(t)
	r := Request{Role: storagecheck.Executor, Name: "worker", Root: f.root,
		EnrolledState: StateDirectory(f.root, storagecheck.Executor, "worker"), User: "debuglet-alt", Group: "debuglet-alt"}
	p, err := Resolve(r, f.assets)
	if err != nil {
		t.Fatal(err)
	}
	p.ExecutorID = uuid.NewString()
	p.PacketCapabilities = true
	p.DispatcherGRPC, p.DispatcherHTTP = "127.0.0.1:9001", "127.0.0.1:9000"
	if err := os.MkdirAll(p.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := storagecheck.BootstrapFresh(t.Context(), storagecheck.Executor, p.DatabasePath); err != nil {
		t.Fatal(err)
	}
	ca, err := testtls.NewAuthority(t.TempDir(), "ca")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ca.Issue(p.ExecutorID, testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"ca.crt": ca.CertPEM, "executor.crt": identity.CertPEM, "executor.key": identity.KeyPEM, "retained-output": []byte("old completed output\n")} {
		if err := os.WriteFile(filepath.Join(p.StateDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := demo.ExecutorConfiguration(testVersion, p.ExecutorID, p.DatabasePath, readiness.Record{GRPCAddr: p.DispatcherGRPC, HTTPAddr: p.DispatcherHTTP})
	cfg["tls"] = map[string]any{"disable": false}
	cfg["credentials"] = map[string]any{"ca_cert": filepath.Join(p.StateDir, "ca.crt"), "client_cert": filepath.Join(p.StateDir, "executor.crt"), "client_key": filepath.Join(p.StateDir, "executor.key")}
	cfg["network"].(map[string]any)["packet_counter"] = "auto"
	if err := demo.WriteConfig(p.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.installer.writeUnit(p); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.manager.unit(p.Unit)
	r.User, r.Group = "", "" // Replacement preserves the retained non-default account.
	return f, p, r
}

func replacementTarget(t *testing.T, f *fixture, p Profile, version, body string) demo.Assets {
	t.Helper()
	a := f.assets
	a.Root = filepath.Join(filepath.Dir(a.Root), version)
	a.CLI, a.Executor = filepath.Join(a.Root, "bin", "dbl"), filepath.Join(a.Root, "bin", "debuglet-executor")
	a.Manifest.Version = version
	if err := os.MkdirAll(filepath.Dir(a.Executor), 0755); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\n[ \"$#\" = 3 ] && [ \"$1\" = -config ] && [ \"$2\" = %q ] && [ \"$3\" = -check-database ] || exit 99\n[ \"$LANG\" = C ] && [ \"$LC_ALL\" = C ] && [ \"$TZ\" = UTC ] && [ -z \"$DEBUGLET_GUEST_WORKER\" ] || exit 98\n%s\n", p.ConfigPath, body)
	if err := os.WriteFile(a.Executor, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return a
}

func replacementSnapshot(t *testing.T, p Profile, metadata bool) map[string]string {
	t.Helper()
	out := map[string]string{}
	paths, err := filepath.Glob(filepath.Join(p.StateDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if metadata {
		paths = append(paths, p.UnitPath, RecordPath(p.Root, p.Role, p.Name))
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		out[path] = fmt.Sprintf("%o:%s", info.Mode().Perm(), data)
	}
	return out
}

func TestReplacePackagePreservesEnrolledStateAndSupportsOldTarget(t *testing.T) {
	f, p, r := enrolledReplacementFixture(t)
	t.Setenv("DEBUGLET_GUEST_WORKER", "must not reach schema process")
	old := replacementTarget(t, f, p, testVersion, "exit 0")
	target := replacementTarget(t, f, p, "1.4.3", "exit 0")
	before := replacementSnapshot(t, p, false)
	for _, a := range []demo.Assets{target, target, old} {
		mark := len(f.manager.recorded())
		report, err := f.installer.ReplacePackage(t.Context(), r, a)
		if err != nil || report.State != "installed" || report.Enabled || !report.Joined || report.Ready || report.ExecutorID != p.ExecutorID {
			t.Fatalf("replacement: %+v, %v", report, err)
		}
		got, err := ReadRecord(f.root, p.Role, p.Name)
		want := p
		want.Version, want.SourceSHA, want.PayloadRoot, want.Executable = a.Manifest.Version, a.Manifest.SourceSHA, a.Root, a.Executor
		if err != nil || got != want {
			t.Fatalf("record: %+v, want %+v, %v", got, want, err)
		}
		if !reflect.DeepEqual(before, replacementSnapshot(t, p, false)) || len(f.chowned) != 0 {
			t.Fatal("replacement modified state or ownership")
		}
		for _, call := range f.manager.recorded()[mark:] {
			if !strings.HasPrefix(call, "state ") && call != "reload" {
				t.Fatalf("replacement drove service: %s", call)
			}
		}
	}
	// Identical version/revision in another verified installation is a path change.
	other := replacementTarget(t, f, p, "other-install", "exit 0")
	other.Manifest = old.Manifest
	if _, err := f.installer.ReplacePackage(t.Context(), r, other); err != nil {
		t.Fatal(err)
	}
	got, _ := ReadRecord(f.root, p.Role, p.Name)
	if got.Executable != other.Executor || got.PayloadRoot != other.Root {
		t.Fatal("target path ignored")
	}
	if _, err := f.installer.Resume(t.Context(), p.Role, p.Name); err != nil {
		t.Fatal(err)
	}
}

func TestReplacePackageRefusalsDoNotMutate(t *testing.T) {
	for _, name := range []string{"enabled", "running", "failed", "pid", "account", "group", "role", "path", "empty identity", "identity", "capabilities", "unit", "schema", "unknown flag", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f, p, r := enrolledReplacementFixture(t)
			body := "exit 0"
			ctx := t.Context()
			switch name {
			case "enabled":
				f.manager.unit(p.Unit).enabled = true
			case "running":
				f.manager.unit(p.Unit).active = "active"
			case "failed":
				f.manager.unit(p.Unit).active = "failed"
			case "pid":
				f.manager.unit(p.Unit).pid = 123
			case "account":
				r.User = "debuglet"
			case "group":
				r.Group = "debuglet"
			case "role":
				r.Role = storagecheck.Dispatcher
			case "path":
				r.EnrolledState = t.TempDir()
			case "empty identity":
				broken := p
				broken.ExecutorID = ""
				if err := writeRecord(broken); err != nil {
					t.Fatal(err)
				}
			case "identity":
				data, _ := os.ReadFile(p.ConfigPath)
				os.WriteFile(p.ConfigPath, []byte(strings.ReplaceAll(string(data), p.ExecutorID, uuid.NewString())), 0600)
			case "capabilities":
				data, _ := os.ReadFile(p.ConfigPath)
				os.WriteFile(p.ConfigPath, []byte(strings.ReplaceAll(string(data), "auto", "fallback")), 0600)
			case "unit":
				data, _ := os.ReadFile(p.UnitPath)
				os.WriteFile(p.UnitPath, append(data, []byte("# unrelated modification\n")...), 0644)
			case "schema":
				body = "echo 'older target refuses this schema' >&2; exit 3"
			case "unknown flag":
				body = "echo 'flag provided but not defined' >&2; exit 2"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			target := replacementTarget(t, f, p, "1.4.3", body)
			before := replacementSnapshot(t, p, true)
			_, err := f.installer.ReplacePackage(ctx, r, target)
			if err == nil {
				t.Fatal("unsafe replacement accepted")
			}
			if name == "schema" && !strings.Contains(err.Error(), "older target refuses this schema") {
				t.Fatalf("target diagnostic lost: %v", err)
			}
			if name == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel cause lost: %v", err)
			}
			if !reflect.DeepEqual(before, replacementSnapshot(t, p, true)) || len(f.chowned) != 0 {
				t.Fatal("refusal changed files or ownership")
			}
		})
	}
}

func TestReplacePackageInterruptedPublicationAndStartGuards(t *testing.T) {
	f, p, r := enrolledReplacementFixture(t)
	target := replacementTarget(t, f, p, "1.4.3", "exit 0")
	before := replacementSnapshot(t, p, false)
	f.manager.reloadErr = errors.New("manager unavailable")
	if _, err := f.installer.ReplacePackage(t.Context(), r, target); err == nil {
		t.Fatal("reload failure lost")
	}
	record, _ := ReadRecord(f.root, p.Role, p.Name)
	if record != p || !strings.Contains(f.unitText(p.Role, p.Name), target.Executor) {
		t.Fatal("interrupted state was not old record/candidate unit")
	}
	f.manager.reloadErr = nil
	marker := filepath.Join(p.StateDir, demo.OfflineStateFile)
	if err := os.WriteFile(marker, []byte("retained marker"), 0600); err != nil {
		t.Fatal(err)
	}
	mark := len(f.manager.recorded())
	if _, err := f.installer.Start(t.Context(), p.Role, p.Name); err == nil {
		t.Fatal("Start accepted mismatch")
	}
	if _, err := f.installer.Resume(t.Context(), p.Role, p.Name); err == nil {
		t.Fatal("Resume accepted mismatch")
	}
	if _, err := f.installer.Install(t.Context(), r, f.assets, false, false); err == nil {
		t.Fatal("ordinary install repaired an interrupted replacement")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("refused start removed marker")
	}
	for _, call := range f.manager.recorded()[mark:] {
		if strings.HasPrefix(call, "start ") || strings.HasPrefix(call, "enable ") {
			t.Fatalf("mismatch drove service: %s", call)
		}
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	other := replacementTarget(t, f, p, "1.4.4", "exit 0")
	if _, err := f.installer.ReplacePackage(t.Context(), r, other); err == nil {
		t.Fatal("different target adopted interrupted unit")
	}
	if _, err := f.installer.ReplacePackage(t.Context(), r, target); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, replacementSnapshot(t, p, false)) {
		t.Fatal("interruption/retry changed state")
	}
	// A completed commit still reloads before starting: the manager may have
	// forgotten its cached definition across an administrator interruption.
	f.manager.loaded = map[string]bool{}
	if _, err := f.installer.Start(t.Context(), p.Role, p.Name); err != nil {
		t.Fatal(err)
	}
}

func TestReplacePackageSchemaCheckDeadline(t *testing.T) {
	f, p, r := enrolledReplacementFixture(t)
	target := replacementTarget(t, f, p, "1.4.3", "exec /bin/sleep 60")
	before := replacementSnapshot(t, p, true)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err := f.installer.ReplacePackage(ctx, r, target)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(began) > 2*time.Second {
		t.Fatalf("schema check not bounded: %v", err)
	}
	if !reflect.DeepEqual(before, replacementSnapshot(t, p, true)) {
		t.Fatal("canceled check changed files")
	}
}

func TestEnrolledInstallRetriesRecordBeforeUnit(t *testing.T) {
	f, p, request := enrolledReplacementFixture(t)
	if err := os.Remove(p.UnitPath); err != nil {
		t.Fatal(err)
	}
	request.User, request.Group = p.User, p.Group
	if _, err := f.installer.Install(t.Context(), request, f.assets, false, false); err != nil {
		t.Fatalf("first adoption record without unit cannot resume: %v", err)
	}
	if err := f.installer.verifyRemoval(t.Context(), p); err != nil {
		t.Fatal(err)
	}
}
