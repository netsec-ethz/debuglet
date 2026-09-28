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

func packageFixture(t *testing.T, prefix, version, component string) string {
	t.Helper()
	root := filepath.Join(prefix, "lib", "debuglet", component, version)
	manifest := artifact.Manifest{SchemaVersion: 1, Version: version, SourceSHA: strings.Repeat("a", 40),
		GoVersion: artifact.Toolchain, GOOS: "linux", GOARCH: "amd64", GuestABI: artifact.GuestABI, Files: map[string]artifact.File{}}
	if component != "" {
		manifest.SchemaVersion, manifest.Component = 2, component
	}
	for name, mode := range artifact.PayloadModesFor(component) {
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
	if err := os.MkdirAll(filepath.Join(root, "share", "debuglet"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, artifact.ManifestPath), data, 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestPruneInactiveVerifiedPackage(t *testing.T) {
	for _, component := range []string{"", "cli", "executor", "dispatcher"} {
		for _, mode := range []string{"inactive", "active", "retained role", "running", "unrelated link", "symlink", "hardlink", "installer lock"} {
			t.Run(component+"/"+mode, func(t *testing.T) {
				f := newFixture(t)
				prefix := t.TempDir()
				candidate := packageFixture(t, prefix, "v0.1.0", component)
				current := packageFixture(t, prefix, "v0.2.0", component)
				command := "dbl"
				if component == "executor" || component == "dispatcher" {
					command = "debuglet-" + component
				}
				if err := os.Mkdir(filepath.Join(prefix, "bin"), 0755); err != nil {
					t.Fatal(err)
				}
				link := "../lib/debuglet/" + filepath.Join(component, "v0.2.0", "bin", command)
				if mode == "active" {
					link = "../lib/debuglet/" + filepath.Join(component, "v0.1.0", "bin", command)
				} else if mode == "unrelated link" {
					link = "/opt/another-cli"
				}
				if err := os.Symlink(link, filepath.Join(prefix, "bin", command)); err != nil {
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
					if err := os.Symlink(filepath.Join(candidate, "bin", command), filepath.Join(proc, "123", "exe")); err != nil {
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
				report, err := f.installer.prune(t.Context(), prefix, "v0.1.0", component, true, proc)
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
					report, err = f.installer.prune(t.Context(), prefix, "v0.1.0", component, false, proc)
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
				if got, err := os.Readlink(filepath.Join(prefix, "bin", command)); err != nil || got != link {
					t.Fatalf("changed entry point: %q, %v", got, err)
				}
				if calls := f.manager.recorded(); len(calls) != 0 {
					t.Fatalf("package prune touched service manager: %v", calls)
				}
			})
		}
	}
}

func TestPruneAcrossPackageLayouts(t *testing.T) {
	for _, tc := range []struct {
		name, candidate, current, pinnedCommand string
	}{
		{name: "full superseded by CLI", current: "cli"},
		{name: "CLI superseded by full", candidate: "cli"},
		{name: "executor superseded by full", candidate: "executor"},
		{name: "dispatcher superseded by full", candidate: "dispatcher"},
		{name: "full still supplies dispatcher", current: "cli", pinnedCommand: "debuglet-dispatcher"},
		{name: "full still supplies executor", current: "cli", pinnedCommand: "debuglet-executor"},
		{name: "command alias keeps package", candidate: "executor", current: "executor", pinnedCommand: "my-executor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			prefix := t.TempDir()
			candidate := packageFixture(t, prefix, "v0.1.0", tc.candidate)
			version := "v0.1.0"
			if tc.candidate == tc.current {
				version = "v0.2.0"
			}
			current := packageFixture(t, prefix, version, tc.current)
			command := "dbl"
			if tc.candidate == "executor" || tc.candidate == "dispatcher" {
				command = "debuglet-" + tc.candidate
			}
			bin := filepath.Join(prefix, "bin")
			if err := os.Mkdir(bin, 0755); err != nil {
				t.Fatal(err)
			}
			link := "../lib/debuglet/" + filepath.Join(tc.current, version, "bin", command)
			if err := os.Symlink(link, filepath.Join(bin, command)); err != nil {
				t.Fatal(err)
			}
			if tc.pinnedCommand != "" {
				targetCommand := tc.pinnedCommand
				if tc.pinnedCommand == "my-executor" {
					targetCommand = "debuglet-executor"
				}
				if err := os.Symlink(filepath.Join(candidate, "bin", targetCommand), filepath.Join(bin, tc.pinnedCommand)); err != nil {
					t.Fatal(err)
				}
			}
			// An unrelated command must survive package removal unchanged.
			if err := os.Symlink("/usr/bin/true", filepath.Join(bin, "unrelated")); err != nil {
				t.Fatal(err)
			}
			report, err := f.installer.prune(t.Context(), prefix, "v0.1.0", tc.candidate, false, t.TempDir())
			if tc.pinnedCommand == "" {
				if err != nil || report.State != "pruned" || report.PackagePath != candidate {
					t.Fatalf("inactive package not pruned: %+v, %v", report, err)
				}
				if _, err := os.Stat(candidate); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("pruned package remains: %v", err)
				}
			} else if err == nil {
				t.Fatal("pruned a package still supplying a command")
			} else if _, err := artifact.Verify(candidate); err != nil {
				t.Fatal("changed protected package", err)
			}
			if _, err := artifact.Verify(current); err != nil {
				t.Fatal("changed current package", err)
			}
			for name, want := range map[string]string{command: link, "unrelated": "/usr/bin/true"} {
				if got, err := os.Readlink(filepath.Join(bin, name)); err != nil || got != want {
					t.Fatalf("changed %s link: %q, %v", name, got, err)
				}
			}
		})
	}
}

func TestPruneRefusesComponentPathMismatch(t *testing.T) {
	for _, mismatch := range []string{"symlink directory", "another component manifest", "invalid component"} {
		t.Run(mismatch, func(t *testing.T) {
			f := newFixture(t)
			prefix := t.TempDir()
			original := packageFixture(t, prefix, "v0.1.0", "cli")
			if err := os.Mkdir(filepath.Join(prefix, "bin"), 0755); err != nil {
				t.Fatal(err)
			}
			component := "executor"
			parent := filepath.Dir(original)
			switch mismatch {
			case "symlink directory":
				if err := os.Symlink(parent, filepath.Join(filepath.Dir(parent), component)); err != nil {
					t.Fatal(err)
				}
			case "another component manifest":
				moved := filepath.Join(filepath.Dir(parent), component)
				if err := os.Rename(parent, moved); err != nil {
					t.Fatal(err)
				}
				original = filepath.Join(moved, "v0.1.0")
			case "invalid component":
				component = "../cli"
			}
			if _, err := f.installer.prune(t.Context(), prefix, "v0.1.0", component, false, t.TempDir()); err == nil {
				t.Fatal("unsafe component path was accepted")
			}
			if _, err := artifact.Verify(original); err != nil {
				t.Fatal("changed the other package", err)
			}
		})
	}
}
