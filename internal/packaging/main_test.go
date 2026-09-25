package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/artifact"
)

func TestCandidateVersion(t *testing.T) {
	t.Chdir(t.TempDir())
	ctx := context.Background()
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "--allow-empty", "-m", "Initial fixture"},
		{"tag", "v1.2.2"},
		{"-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "--allow-empty", "-m", "Current fixture"},
		{"tag", "v1.2.3"},
	} {
		if _, err := command(ctx, "git", args...); err != nil {
			t.Fatal(err)
		}
	}
	sha, err := command(ctx, "git", "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, tag, protected, want string
	}{
		{"branch", "", "false", "v0.0.0-dev." + sha[:12]},
		{"protected branch", "", "true", "v0.0.0-dev." + sha[:12]},
		{"protected exact tag", "v1.2.3", "true", "v1.2.3"},
		{"unprotected tag", "v1.2.3", "false", ""},
		{"missing protection", "v1.2.3", "", ""},
		{"invalid tag", "v01.2.3", "true", ""},
		{"missing tag", "v9.9.9", "true", ""},
		{"different revision", "v1.2.2", "true", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CI_COMMIT_TAG", tc.tag)
			t.Setenv("CI_COMMIT_REF_PROTECTED", tc.protected)
			got, err := candidateVersion(ctx, sha)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("accepted release tag %q", tc.tag)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("version = %q, error = %v; want %q", got, err, tc.want)
			}
		})
	}
}

func packageFixture(t *testing.T) (string, string, buildRecord) {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)
	dist := filepath.Join(root, "dist")
	if err := os.Mkdir(dist, 0700); err != nil {
		t.Fatal(err)
	}
	r := buildRecord{Metadata: artifact.Manifest{SchemaVersion: 1, Version: "v0.0.0-dev.aaaaaaaaaaaa", SourceSHA: strings.Repeat("a", 40), GoVersion: artifact.Toolchain, GOOS: "linux", GOARCH: "amd64", GuestABI: artifact.GuestABI, Files: map[string]artifact.File{}}, Compiled: map[string]artifact.File{}}
	for name := range targets {
		path := filepath.Join(dist, name)
		if err := os.WriteFile(path, []byte("compiled fixture: "+name), 0644); err != nil {
			t.Fatal(err)
		}
		f, err := artifact.HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		r.Compiled[name] = f
	}
	if err := writeJSON(filepath.Join(dist, "build-record.json"), r); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("scripts", 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"LICENSE": "fixture license", "README-install.md": "@VERSION@ @SOURCE_SHA@", "scripts/install.sh": "@VERSION@\n@SOURCE_SHA@\n@PAYLOAD_SUMS@\n"} {
		if err := os.WriteFile(name, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dist, filepath.Join(root, "packages"), r
}
func TestCandidateArchive(t *testing.T) {
	dist, out, r := packageFixture(t)
	if err := packWithCopy(dist, out, r.Metadata.SourceSHA, copyFile); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(out, "debuglet-"+r.Metadata.Version+"-linux-amd64.tar.gz")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if seen[h.Name] {
			t.Fatal("duplicate member")
		}
		seen[h.Name] = true
		mode, ok := artifact.PayloadModes()[h.Name]
		if !ok || h.Typeflag != tar.TypeReg || h.Mode != int64(mode) || h.Uid != 0 || h.Gid != 0 {
			t.Fatalf("invalid header %+v", h)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == artifact.ManifestPath {
			m, err := artifact.DecodeManifest(data)
			if err != nil {
				t.Fatal(err)
			}
			if m.SourceSHA != r.Metadata.SourceSHA || m.Files["bin/dbl"] != r.Compiled["dbl"] || m.Files["share/debuglet/hello.wasm"] != r.Compiled["hello.wasm"] {
				t.Fatal("lost build identity")
			}
		}
	}
	if len(seen) != 8 || !seen["share/debuglet/hello.wasm"] {
		t.Fatalf("members %v", seen)
	}
	installer, err := os.ReadFile(filepath.Join(out, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(installer, []byte("@")) || !bytes.Contains(installer, []byte(artifact.ManifestPath)) {
		t.Fatal("unrendered installer identity")
	}
}
func TestPackageDetectsCopyMutation(t *testing.T) {
	dist, out, r := packageFixture(t)
	mutated := false
	copier := func(source, dest string, mode os.FileMode) error {
		if !mutated && filepath.Dir(source) == dist {
			mutated = true
			if err := os.WriteFile(source, []byte("changed after record validation"), 0644); err != nil {
				return err
			}
		}
		return copyFile(source, dest, mode)
	}
	if err := packWithCopy(dist, out, r.Metadata.SourceSHA, copier); err == nil {
		t.Fatal("packaged changed compiled bytes")
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("published a candidate after identity failure")
	}
}
func TestBuildRecordValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"null files", func(b []byte) []byte { return bytes.Replace(b, []byte(`"files": {}`), []byte(`"files": null`), 1) }},
		{"missing files", func(b []byte) []byte { return bytes.Replace(b, []byte("    \"files\": {},\n"), nil, 1) }},
		{"duplicate metadata", func(b []byte) []byte { return append([]byte(`{"metadata":{},`), b[1:]...) }},
		{"wrong-case field", func(b []byte) []byte { return bytes.Replace(b, []byte(`"bytes":`), []byte(`"Bytes":`), 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dist, _, r := packageFixture(t)
			path := filepath.Join(dist, "build-record.json")
			old, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data := tc.change(old)
			if bytes.Equal(data, old) {
				t.Fatal("fixture mutation had no effect")
			}
			if err := os.WriteFile(path, data, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRecord(dist, r.Metadata.SourceSHA); err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "record")
		if err := os.WriteFile(path, make([]byte, 64*1024+1), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBuildRecord(path); err == nil {
			t.Fatal("oversized record accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "link")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := readBuildRecord(path); err == nil {
			t.Fatal("symlink accepted")
		}
	})
}
func TestDemoEvidenceRequiresActualPass(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		ok         bool
	}{
		{"pass", `{"Action":"pass","Test":"TestInstalledDemoAcceptance","Package":"github.com/netsec-ethz/debuglet/internal/demo"}`, true},
		{"empty", "", false}, {"renamed", `{"Action":"pass","Test":"Other"}`, false},
		{"skip", `{"Action":"skip","Test":"TestInstalledDemoAcceptance"}`, false}, {"bad JSON", "{", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "events")
			if err := os.WriteFile(p, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := checkDemoEvidence(p); (err == nil) != tc.ok {
				t.Fatalf("result %v", err)
			}
		})
	}
}
func TestCompatibilityEvidenceRequiresActualPass(t *testing.T) {
	const pkg = "github.com/netsec-ethz/debuglet/internal/acceptance/canary"
	const passed = `{"Action":"pass","Test":"TestCanaryLocal","Package":"` + pkg + `"}`
	for _, tc := range []struct {
		name, data string
		ok         bool
	}{
		{"pass", passed, true},
		{"empty", "", false},
		{"wrong test", `{"Action":"pass","Test":"Other","Package":"` + pkg + `"}`, false},
		{"wrong package", `{"Action":"pass","Test":"TestCanaryLocal","Package":"other"}`, false},
		{"duplicate pass", passed + "\n" + passed, false},
		{"pass then package failure", passed + "\n" + `{"Action":"fail","Package":"` + pkg + `"}`, false},
		{"pass then subtest skip", passed + "\n" + `{"Action":"skip","Test":"TestCanaryLocal/cleanup"}`, false},
		{"trailing malformed event", passed + "\n{", false},
		{"null event", passed + "\nnull", false},
		{"empty event", passed + "\n{}", false},
		{"unknown action", passed + "\n" + `{"Action":"unknown"}`, false},
		{"overwritten failure", `{"Action":"fail","Action":"pass","Test":"TestCanaryLocal","Package":"` + pkg + `"}`, false},
		{"aliased failure", `{"Action":"fail","action":"pass","Test":"TestCanaryLocal","Package":"` + pkg + `"}`, false},
		{"aliased action", `{"action":"pass","Test":"TestCanaryLocal","Package":"` + pkg + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := checkTestEvidence(path, pkg, "TestCanaryLocal"); (err == nil) != tc.ok {
				t.Fatalf("result %v", err)
			}
		})
	}
}

func TestCompatibilityChecksBytesBeforeInstaller(t *testing.T) {
	// The sentinel installer exits before any build. Its invocation is the
	// positive control; a changed payload must fail before that invocation.
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "ci-compatibility.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid hashes", "changed installer", "changed archive", "missing installer hash", "unexpected member", "unterminated duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"scripts", "packages"} {
				if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(name string, data []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("scripts/ci-compatibility.sh", script)
			const archiveName = "debuglet-v0.0.0-dev.aaaaaaaaaaaa-linux-amd64.tar.gz"
			archive := []byte("fixture archive bytes")
			installer := []byte("#!/bin/sh\nprintf 'ran' > .installer-ran\nexit 93\n")
			write("packages/"+archiveName, archive)
			write("packages/install.sh", installer)
			sums := fmt.Sprintf("%x  %s\n%x  install.sh\n", sha256.Sum256(archive), archiveName, sha256.Sum256(installer))
			switch scenario {
			case "changed installer":
				write("packages/install.sh", append(installer, []byte("# changed\n")...))
			case "changed archive":
				write("packages/"+archiveName, []byte("changed fixture archive"))
			case "missing installer hash":
				sums = fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), archiveName)
			case "unexpected member":
				sums += fmt.Sprintf("%x  unexpected\n", sha256.Sum256(nil))
			case "unterminated duplicate":
				sums += fmt.Sprintf("%x  install.sh", sha256.Sum256(installer))
			}
			write("packages/SHA256SUMS", []byte(sums))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts", "ci-compatibility.sh"))
			cmd.Env = append(os.Environ(), "COMPAT_ARCHIVE="+filepath.Join(root, "packages", archiveName), "COMPAT_SHA256SUMS="+filepath.Join(root, "packages", "SHA256SUMS"))
			cmd.WaitDelay = time.Second
			output, runErr := cmd.CombinedOutput()
			if ctx.Err() != nil || runErr == nil {
				t.Fatalf("expected a bounded nonzero exit; context=%v error=%v output=%s", ctx.Err(), runErr, output)
			}
			_, markerErr := os.Stat(filepath.Join(root, ".installer-ran"))
			if scenario == "valid hashes" {
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) || exit.ExitCode() != 93 || markerErr != nil {
					t.Fatalf("positive control did not reach installer: %v marker=%v output=%s", runErr, markerErr, output)
				}
			} else if !os.IsNotExist(markerErr) {
				t.Fatalf("invalid candidate reached installer: %v output=%s", markerErr, output)
			}
		})
	}
}

func TestSelectedCompilerVersion(t *testing.T) {
	for _, version := range []string{"go version go1.25.11 linux/amd64", "go version go1.24.0 linux/amd64"} {
		t.Run(version, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "compiler")
			body := "#!/bin/sh\nprintf '%s\\n' '" + version + "'\n"
			if err := os.WriteFile(path, []byte(body), 0755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := verifyCompiler(ctx, path)
			if (err == nil) != (version == "go version go1.25.11 linux/amd64") {
				t.Fatalf("compiler result %v", err)
			}
		})
	}
}
