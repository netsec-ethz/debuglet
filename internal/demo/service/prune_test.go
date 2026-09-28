package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/demo"
)

func packageFixture(t *testing.T, prefix, version string) string {
	t.Helper()
	root := filepath.Join(prefix, "lib", "debuglet", version)
	manifest := artifact.Manifest{SchemaVersion: 1, Version: version, SourceSHA: strings.Repeat("a", 40),
		GoVersion: artifact.Toolchain, GOOS: "linux", GOARCH: "amd64", GuestABI: artifact.GuestABI, Files: map[string]artifact.File{}}
	for name, mode := range artifact.PayloadModes() {
		if name == artifact.ManifestPath {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("payload "+name), mode); err != nil {
			t.Fatal(err)
		}
		file, err := artifact.HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files[name] = file
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, artifact.ManifestPath), data, 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestPruneInactiveVerifiedPackage(t *testing.T) {
	for _, mode := range []string{"inactive", "active", "retained role", "running", "unrelated link", "symlink", "hardlink", "installer lock"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			prefix := t.TempDir()
			candidate := packageFixture(t, prefix, "v0.1.0")
			current := packageFixture(t, prefix, "v0.2.0")
			if err := os.Mkdir(filepath.Join(prefix, "bin"), 0755); err != nil {
				t.Fatal(err)
			}
			link := "../lib/debuglet/v0.2.0/bin/dbl"
			if mode == "active" {
				link = "../lib/debuglet/v0.1.0/bin/dbl"
			} else if mode == "unrelated link" {
				link = "/opt/another-cli"
			}
			if err := os.Symlink(link, filepath.Join(prefix, "bin", "dbl")); err != nil {
				t.Fatal(err)
			}
			proc := t.TempDir()
			switch mode {
			case "retained role":
				p, err := DerivePaths(f.root, demo.ExecutorSchema, "worker")
				if err != nil {
					t.Fatal(err)
				}
				p.PayloadRoot = candidate
				if err := writeRecord(p); err != nil {
					t.Fatal(err)
				}
			case "running":
				if err := os.Mkdir(filepath.Join(proc, "123"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(candidate, "bin", "debuglet-executor"), filepath.Join(proc, "123", "exe")); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				path := filepath.Join(candidate, "LICENSE")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				makeLink := os.Link
				if mode == "symlink" {
					makeLink = os.Symlink
				}
				if err := makeLink(filepath.Join(current, "LICENSE"), path); err != nil {
					t.Fatal(err)
				}
			case "installer lock":
				if err := os.Mkdir(filepath.Join(prefix, "lib", "debuglet", ".install.lock"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			report, err := f.installer.prune(t.Context(), prefix, "v0.1.0", true, proc)
			if mode != "inactive" {
				if err == nil {
					t.Fatal("unsafe prune was accepted")
				}
			} else {
				if err != nil || report.State != "retained" {
					t.Fatalf("dry run: %+v, %v", report, err)
				}
				if _, err := os.Stat(candidate); err != nil {
					t.Fatal("dry run removed package", err)
				}
				report, err = f.installer.prune(t.Context(), prefix, "v0.1.0", false, proc)
				if err != nil || report.State != "pruned" {
					t.Fatalf("prune: %+v, %v", report, err)
				}
			}
			if _, err := os.Stat(candidate); (mode == "inactive") != errors.Is(err, os.ErrNotExist) {
				t.Fatalf("candidate survival does not match outcome: %v", err)
			}
			if _, err := artifact.Verify(current); err != nil {
				t.Fatal("changed current package", err)
			}
			if got, err := os.Readlink(filepath.Join(prefix, "bin", "dbl")); err != nil || got != link {
				t.Fatalf("changed entry point: %q, %v", got, err)
			}
			if calls := f.manager.recorded(); len(calls) != 0 {
				t.Fatalf("package prune touched service manager: %v", calls)
			}
		})
	}
}
