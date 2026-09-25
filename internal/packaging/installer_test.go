//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/artifact"
)

const installerFixtureVersion = "v0.0.0-dev.aaaaaaaaaaaa"

type installerMember struct {
	name string
	mode int64
	kind byte
	link string
	data []byte
}

type installerFixture struct {
	t         *testing.T
	directory string
	installer string
	archive   string
	checksums string
	prefix    string
	version   string
	members   []installerMember
}

func newInstallerFixture(t *testing.T) *installerFixture {
	t.Helper()
	return newInstallerVersionFixture(t, installerFixtureVersion)
}

func newInstallerVersionFixture(t *testing.T, version string) *installerFixture {
	t.Helper()
	f := &installerFixture{t: t, directory: t.TempDir(), prefix: filepath.Join(t.TempDir(), "prefix with spaces"), version: version}
	f.installer = filepath.Join(f.directory, "install.sh")
	f.archive = filepath.Join(f.directory, "debuglet-"+version+"-linux-amd64.tar.gz")
	f.checksums = filepath.Join(f.directory, "SHA256SUMS")
	f.members = []installerMember{
		{name: "LICENSE", mode: 0644, data: []byte("fixture license\n")},
		{name: "README-install.md", mode: 0644, data: []byte("installer fixture, not a Debuglet runtime\n")},
		{name: "bin/dbl", mode: 0755, data: []byte("#!/bin/sh\nprintf 'installed fixture\\n'\n")},
		{name: "bin/debuglet-dispatcher", mode: 0755, data: []byte("#!/bin/sh\nexit 0\n")},
		{name: "bin/debuglet-executor", mode: 0755, data: []byte("#!/bin/sh\nexit 0\n")},
		{name: "share/debuglet/demo.wasm", mode: 0644, data: []byte("fixture guest bytes")},
		{name: "share/debuglet/hello.wasm", mode: 0644, data: []byte("fixture hello guest bytes")},
		{name: "share/debuglet/manifest.json", mode: 0644, data: []byte(`{"fixture":true,"build_pipeline_url":"fixture-one"}`)},
	}
	template, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	for _, member := range f.members {
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(member.data), member.name)
	}
	installer := strings.NewReplacer("@VERSION@", version, "@SOURCE_SHA@", strings.Repeat("a", 40), "@PAYLOAD_SUMS@", strings.TrimSuffix(sums.String(), "\n")).Replace(string(template))
	installerWrite(t, f.installer, []byte(installer), 0755)
	f.writeArchive(f.members)
	return f
}

func installerWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func (f *installerFixture) writeArchive(members []installerMember) {
	f.t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	w := tar.NewWriter(gz)
	for _, member := range members {
		kind := member.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: member.name, Mode: member.mode, Typeflag: kind, Linkname: member.link, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if kind == tar.TypeReg {
			header.Size = int64(len(member.data))
		}
		if err := w.WriteHeader(header); err != nil {
			f.t.Fatal(err)
		}
		if kind == tar.TypeReg {
			if _, err := w.Write(member.data); err != nil {
				f.t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		f.t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		f.t.Fatal(err)
	}
	installerWrite(f.t, f.archive, data.Bytes(), 0644)
	f.writeChecksums()
}

func (f *installerFixture) writeChecksums() {
	f.t.Helper()
	var sums strings.Builder
	for _, path := range []string{f.archive, f.installer} {
		data, err := os.ReadFile(path)
		if err != nil {
			f.t.Fatal(err)
		}
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(data), filepath.Base(path))
	}
	installerWrite(f.t, f.checksums, []byte(sums.String()), 0644)
}

func (f *installerFixture) command(environment ...string) *exec.Cmd {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.t.Context(), 8*time.Second)
	f.t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "sh", f.installer, "--archive", f.archive, "--checksums", f.checksums, "--version", f.version, "--prefix", f.prefix)
	cmd.Dir = f.t.TempDir()
	cmd.Env = append(os.Environ(), environment...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	return cmd
}

func (f *installerFixture) run(wantSuccess bool, environment ...string) string {
	f.t.Helper()
	output, err := f.command(environment...).CombinedOutput()
	if (err == nil) != wantSuccess {
		f.t.Fatalf("installer success=%v, want %v: %v\n%s", err == nil, wantSuccess, err, output)
	}
	f.assertTemporaryCleanup()
	return string(output)
}

func (f *installerFixture) destination() string {
	return filepath.Join(f.prefix, "lib", "debuglet", f.version)
}

func (f *installerFixture) assertTemporaryCleanup() {
	f.t.Helper()
	for _, dir := range []string{filepath.Join(f.prefix, "lib", "debuglet"), filepath.Join(f.prefix, "bin")} {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			f.t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".install-stage.") || strings.HasPrefix(entry.Name(), ".dbl-link.") {
				f.t.Errorf("installer left temporary state: %s", filepath.Join(dir, entry.Name()))
			}
		}
	}
}

func (f *installerFixture) assertNoPublishedVersion() {
	f.t.Helper()
	for _, path := range []string{f.destination(), filepath.Join(f.prefix, "bin", "dbl"), filepath.Join(f.prefix, "lib", "debuglet", ".install.lock")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			f.t.Errorf("unexpected installed state %s: %v", path, err)
		}
	}
}

func (f *installerFixture) writePayload(root string) {
	f.t.Helper()
	for _, member := range f.members {
		installerWrite(f.t, filepath.Join(root, filepath.FromSlash(member.name)), member.data, os.FileMode(member.mode))
	}
}

func (f *installerFixture) assertInstalled() {
	f.t.Helper()
	link := filepath.Join(f.prefix, "bin", "dbl")
	if got, err := os.Readlink(link); err != nil || got != "../lib/debuglet/"+f.version+"/bin/dbl" {
		f.t.Fatalf("managed link: %q, %v", got, err)
	}
	for _, member := range f.members {
		path := filepath.Join(f.destination(), filepath.FromSlash(member.name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(member.mode) {
			f.t.Fatalf("installed mode %s: %v, %v", member.name, info, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, member.data) {
			f.t.Fatalf("installed payload %s: %q, %v", member.name, got, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(f.prefix, "lib", "debuglet", ".install.lock")); !errors.Is(err, os.ErrNotExist) {
		f.t.Fatalf("installer lock not released: %v", err)
	}
}

func TestInstaller(t *testing.T) {
	t.Run("spaces and identical rerun", func(t *testing.T) {
		f := newInstallerFixture(t)
		f.run(true)
		f.assertInstalled()
		before, err := os.Stat(f.destination())
		if err != nil {
			t.Fatal(err)
		}
		f.run(true)
		after, err := os.Stat(f.destination())
		if err != nil || !os.SameFile(before, after) {
			t.Fatalf("identical rerun replaced the version directory: %v", err)
		}
		// This executes only the fixture script through the installed symlink.
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, filepath.Join(f.prefix, "bin", "dbl")).CombinedOutput()
		if err != nil || string(output) != "installed fixture\n" {
			t.Fatalf("installed fixture symlink execution: %q, %v", output, err)
		}
	})

	t.Run("archive order is immaterial", func(t *testing.T) {
		f := newInstallerFixture(t)
		members := slices.Clone(f.members)
		slices.Reverse(members)
		f.writeArchive(members)
		f.run(true)
		f.assertInstalled()
	})

	for _, kind := range []string{"archive", "installer", "extra checksum", "duplicate checksum", "missing checksum", "invalid checksum"} {
		t.Run("reject "+kind+" before creating prefix", func(t *testing.T) {
			f := newInstallerFixture(t)
			switch kind {
			case "archive", "installer":
				path := f.archive
				if kind == "installer" {
					path = f.installer
				}
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString("\n# changed\n"); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			default:
				data, err := os.ReadFile(f.checksums)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.SplitAfter(string(data), "\n")
				switch kind {
				case "extra checksum":
					data = append(data, []byte(strings.Repeat("a", 64)+"  unexpected\n")...)
				case "duplicate checksum":
					data = append(data, []byte(lines[0])...)
				case "missing checksum":
					data = []byte(lines[0])
				case "invalid checksum":
					data[0] = 'z'
				}
				installerWrite(t, f.checksums, data, 0644)
			}
			f.run(false)
			if _, err := os.Lstat(f.prefix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("created prefix before checksum validation: %v", err)
			}
		})
	}

	for _, version := range []string{"v1.2.3", "v01.2.3", "v1.2", "v1.2.3/../../outside", "v1.2.3-", "v1.2.3-..", "v1.2.3+build"} {
		t.Run("reject version "+version, func(t *testing.T) {
			f := newInstallerFixture(t)
			cmd := f.command()
			cmd.Args[len(cmd.Args)-3] = version
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("accepted version %q: %s", version, output)
			}
			if _, err := os.Lstat(f.prefix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("created prefix for invalid version: %v", err)
			}
		})
	}

	for _, kind := range []string{"traversal", "absolute", "dot prefix", "duplicate", "extra file", "directory", "symlink", "hardlink", "fifo", "mode", "setuid", "newline name", "payload digest", "manifest identity"} {
		t.Run("reject archive "+kind, func(t *testing.T) {
			f := newInstallerFixture(t)
			outside := filepath.Join(t.TempDir(), "untouched")
			installerWrite(t, outside, []byte("keep"), 0644)
			members := slices.Clone(f.members)
			switch kind {
			case "traversal":
				members[2].name = "../untouched"
			case "absolute":
				members[2].name = outside
			case "dot prefix":
				members[2].name = "./bin/dbl"
			case "duplicate":
				members = append(members, members[2])
			case "extra file":
				members = append(members, installerMember{name: "unexpected", mode: 0644, data: []byte("extra")})
			case "directory":
				members = append(members, installerMember{name: "bin/", kind: tar.TypeDir, mode: 0755})
			case "symlink":
				members[2].kind, members[2].link = tar.TypeSymlink, outside
			case "hardlink":
				members[2].kind, members[2].link = tar.TypeLink, "LICENSE"
			case "fifo":
				members[2].kind = tar.TypeFifo
			case "mode":
				members[2].mode = 0744
			case "setuid":
				members[2].mode = 04755
			case "newline name":
				members[2].name = "bin/dbl\n"
			case "payload digest":
				members[2].data = []byte("changed payload")
			case "manifest identity":
				members[7].data = []byte(`{"fixture":true,"build_pipeline_url":"fixture-two"}`)
			}
			f.writeArchive(members) // The detached checksums are valid for this malformed archive.
			output := f.run(false)
			if (kind == "payload digest" || kind == "manifest identity") && !strings.Contains(output, "checksum mismatch:") {
				t.Fatalf("did not reach extracted payload verification: %s", output)
			}
			f.assertNoPublishedVersion()
			if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
				t.Fatalf("archive touched unrelated data: %q, %v", data, err)
			}
		})
	}

	for _, location := range []string{"prefix", "ancestor", "bin", "lib", "lib/debuglet"} {
		t.Run("reject symlink at "+location, func(t *testing.T) {
			f := newInstallerFixture(t)
			target := t.TempDir()
			path := f.prefix
			if location == "ancestor" {
				f.prefix = filepath.Join(path, "nested prefix")
			} else if location != "prefix" {
				path = filepath.Join(path, filepath.FromSlash(location))
			}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			f.run(false)
			if got, err := os.Readlink(path); err != nil || got != target {
				t.Fatalf("symlink changed: %q, %v", got, err)
			}
			entries, err := os.ReadDir(target)
			if err != nil || len(entries) != 0 {
				t.Fatalf("installer wrote through symlink: %v, %v", entries, err)
			}
		})
	}

	for _, kind := range []string{"regular file", "directory", "unrelated symlink", "absolute symlink", "dangling managed symlink", "invalid managed version"} {
		t.Run("preserve existing CLI "+kind, func(t *testing.T) {
			f := newInstallerFixture(t)
			cli := filepath.Join(f.prefix, "bin", "dbl")
			if err := os.MkdirAll(filepath.Dir(cli), 0755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "regular file":
				installerWrite(t, cli, []byte("unrelated CLI"), 0755)
			case "directory":
				if err := os.Mkdir(cli, 0755); err != nil {
					t.Fatal(err)
				}
			default:
				link := "unrelated"
				if kind == "absolute symlink" {
					link = "/bin/sh"
				}
				if kind == "dangling managed symlink" {
					link = "../lib/debuglet/v1.2.3/bin/dbl"
				}
				if kind == "invalid managed version" {
					link = "../lib/debuglet/v01.2.3/bin/dbl"
				}
				if err := os.Symlink(link, cli); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(cli)
			if err != nil {
				t.Fatal(err)
			}
			f.run(false)
			after, err := os.Lstat(cli)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("replaced unrelated CLI: %v", err)
			}
			if _, err := os.Lstat(f.destination()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("published version for unrelated CLI: %v", err)
			}
		})
	}

	t.Run("update a managed prior version", func(t *testing.T) {
		f := newInstallerFixture(t)
		previous := filepath.Join(f.prefix, "lib", "debuglet", "v1.2.3-rc.1")
		f.writePayload(previous)
		if err := os.MkdirAll(filepath.Join(f.prefix, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../lib/debuglet/v1.2.3-rc.1/bin/dbl", filepath.Join(f.prefix, "bin", "dbl")); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(previous)
		if err != nil {
			t.Fatal(err)
		}
		f.run(true)
		f.assertInstalled()
		after, err := os.Stat(previous)
		if err != nil || !os.SameFile(before, after) {
			t.Fatalf("old version changed: %v", err)
		}
	})

	for _, kind := range []string{"manifest bytes", "mode", "extra file", "hidden file", "symlink payload", "symlink root", "unrelated directory"} {
		t.Run("preserve conflicting version "+kind, func(t *testing.T) {
			f := newInstallerFixture(t)
			f.writePayload(f.destination())
			switch kind {
			case "manifest bytes":
				installerWrite(t, filepath.Join(f.destination(), "share/debuglet/manifest.json"), []byte("different pipeline identity"), 0644)
			case "mode":
				if err := os.Chmod(filepath.Join(f.destination(), "bin/dbl"), 0700); err != nil {
					t.Fatal(err)
				}
			case "extra file", "hidden file":
				name := "extra"
				if kind == "hidden file" {
					name = ".extra"
				}
				installerWrite(t, filepath.Join(f.destination(), name), []byte("unrelated"), 0644)
			case "symlink payload":
				path := filepath.Join(f.destination(), "bin/dbl")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/bin/sh", path); err != nil {
					t.Fatal(err)
				}
			case "symlink root":
				original := f.destination() + "-saved"
				if err := os.Rename(f.destination(), original); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(original, f.destination()); err != nil {
					t.Fatal(err)
				}
			case "unrelated directory":
				if err := os.RemoveAll(f.destination()); err != nil {
					t.Fatal(err)
				}
				installerWrite(t, filepath.Join(f.destination(), "keep"), []byte("unrelated"), 0644)
			}
			before, err := os.Lstat(f.destination())
			if err != nil {
				t.Fatal(err)
			}
			output := f.run(false)
			if !strings.Contains(output, "existing version conflicts") {
				t.Fatalf("did not validate the existing version: %s", output)
			}
			after, err := os.Lstat(f.destination())
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("conflicting version was replaced: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(f.prefix, "bin", "dbl")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("switched CLI to conflicting version: %v", err)
			}
		})
	}

	if os.Geteuid() == 0 {
		for _, location := range []string{"prefix", "bin", "lib", "lib/debuglet"} {
			t.Run("reject foreign owner "+location, func(t *testing.T) {
				f := newInstallerFixture(t)
				path := f.prefix
				if location != "prefix" {
					path = filepath.Join(path, location)
				}
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, 65534, 65534); err != nil {
					t.Fatal(err)
				}
				f.run(false)
				f.assertNoPublishedVersion()
			})
		}
	}
}

// Exercise actual rendered installers against the packaging validator. This
// freezes the supported version subset without silently expanding either side
// to all SemVer spellings (for example, internal prerelease hyphens).
func TestInstallerVersionContract(t *testing.T) {
	for _, test := range []struct {
		version string
		valid   bool
	}{
		{"v0.0.0", true},
		{"v12.34.56", true},
		{"v1.2.3-rc.1", true},
		{"v1.2.3-alphaBeta.001", true},
		{"v1.2.3-" + strings.Repeat("a", 121), true},
		{"v1.2.3-" + strings.Repeat("a", 122), false},
		{"v01.2.3", false},
		{"v1.2.3-rc-1", false},
		{"v1.2.3-alpha..beta", false},
		{"v1.2.3+build", false},
	} {
		t.Run(test.version, func(t *testing.T) {
			if got := artifact.ValidVersion(test.version); got != test.valid {
				t.Fatalf("packaging version contract changed: got %v, want %v", got, test.valid)
			}
			f := newInstallerVersionFixture(t, test.version)
			f.run(test.valid)
			if test.valid {
				f.assertInstalled()
			} else if _, err := os.Lstat(f.prefix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid candidate created prefix: %v", err)
			}
		})
	}
}

func TestInstallerOwnershipLifecycle(t *testing.T) {
	t.Run("archive environment cannot transform members", func(t *testing.T) {
		f := newInstallerFixture(t)
		f.run(true, "TAR_OPTIONS=--transform=s@bin/dbl@unexpected@", "GZIP=--invalid-fixture-option")
		f.assertInstalled()
	})

	t.Run("managed link preserves exact trailing bytes", func(t *testing.T) {
		f := newInstallerFixture(t)
		f.writePayload(filepath.Join(f.prefix, "lib", "debuglet", "v1.2.3"))
		cli := filepath.Join(f.prefix, "bin", "dbl")
		if err := os.MkdirAll(filepath.Dir(cli), 0755); err != nil {
			t.Fatal(err)
		}
		link := "../lib/debuglet/v1.2.3/bin/dbl\n"
		if err := os.Symlink(link, cli); err != nil {
			t.Fatal(err)
		}
		f.run(false)
		if got, err := os.Readlink(cli); err != nil || got != link {
			t.Fatalf("changed an unrelated link after trimming its bytes: %q, %v", got, err)
		}
		if _, err := os.Lstat(f.destination()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("published candidate for unrelated link: %v", err)
		}
	})

	t.Run("version appearing before rename is preserved", func(t *testing.T) {
		f := newInstallerFixture(t)
		realMV, err := exec.LookPath("mv")
		if err != nil {
			t.Fatal(err)
		}
		wrapper := t.TempDir()
		// Simulate unrelated state appearing after the absence check. GNU mv
		// must not replace it; the installer must detect the skipped move.
		script := "#!/bin/sh\nmkdir -- " + installerShellQuote(f.destination()) + " || exit $?\nprintf 'keep' > " + installerShellQuote(filepath.Join(f.destination(), "unrelated")) + "\nexec " + installerShellQuote(realMV) + " \"$@\"\n"
		installerWrite(t, filepath.Join(wrapper, "mv"), []byte(script), 0755)
		output := f.run(false, "PATH="+wrapper+":"+os.Getenv("PATH"))
		if !strings.Contains(output, "destination appeared during publication") {
			t.Fatalf("did not reach the guarded publication race: %s", output)
		}
		if got, err := os.ReadFile(filepath.Join(f.destination(), "unrelated")); err != nil || string(got) != "keep" {
			t.Fatalf("removed unrelated destination state: %q, %v", got, err)
		}
		if _, err := os.Lstat(filepath.Join(f.prefix, "bin", "dbl")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("published link after a skipped version move: %v", err)
		}
	})

	t.Run("held lock is preserved", func(t *testing.T) {
		f := newInstallerFixture(t)
		lockFile := filepath.Join(f.prefix, "lib", "debuglet", ".install.lock", "owner")
		installerWrite(t, lockFile, []byte("another invocation"), 0600)
		start := time.Now()
		f.run(false)
		if time.Since(start) > 2*time.Second {
			t.Fatal("held lock did not fail promptly")
		}
		if got, err := os.ReadFile(lockFile); err != nil || string(got) != "another invocation" {
			t.Fatalf("removed another invocation's lock: %q, %v", got, err)
		}
	})

	t.Run("resume after version publication", func(t *testing.T) {
		f := newInstallerFixture(t)
		realMV, err := exec.LookPath("mv")
		if err != nil {
			t.Fatal(err)
		}
		wrapper := t.TempDir()
		// The actual version rename succeeds, then the supervised invocation
		// fails before publishing bin/dbl. There is no production fault switch.
		script := "#!/bin/sh\n" + installerShellQuote(realMV) + " \"$@\" || exit $?\nexit 9\n"
		installerWrite(t, filepath.Join(wrapper, "mv"), []byte(script), 0755)
		f.run(false, "PATH="+wrapper+":"+os.Getenv("PATH"))
		before, err := os.Stat(f.destination())
		if err != nil {
			t.Fatalf("version publication did not happen: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(f.prefix, "bin", "dbl")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("CLI switched before injected failure: %v", err)
		}
		f.run(true)
		f.assertInstalled()
		after, err := os.Stat(f.destination())
		if err != nil || !os.SameFile(before, after) {
			t.Fatalf("recovery replaced the published version: %v", err)
		}
	})

	for _, interrupt := range []bool{false, true} {
		name := "concurrent installers serialize"
		if interrupt {
			name = "TERM releases only owned state"
		}
		t.Run(name, func(t *testing.T) {
			f := newInstallerFixture(t)
			realTar, err := exec.LookPath("tar")
			if err != nil {
				t.Fatal(err)
			}
			wrapper := t.TempDir()
			reached, release := filepath.Join(wrapper, "reached"), filepath.Join(wrapper, "release")
			script := "#!/bin/sh\n: > " + installerShellQuote(reached) + "\nwhile [ ! -f " + installerShellQuote(release) + " ]; do sleep 0.01; done\nexec " + installerShellQuote(realTar) + " \"$@\"\n"
			installerWrite(t, filepath.Join(wrapper, "tar"), []byte(script), 0755)
			cmd := f.command("PATH=" + wrapper + ":" + os.Getenv("PATH"))
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			joined := false
			t.Cleanup(func() {
				if !joined {
					syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					<-done
				}
			})
			deadline := time.After(3 * time.Second)
			for {
				if _, err := os.Stat(reached); err == nil {
					break
				}
				select {
				case err := <-done:
					joined = true
					t.Fatalf("installer ended before barrier: %v\n%s", err, &output)
				case <-deadline:
					t.Fatal("installer did not reach owned stage")
				case <-time.After(5 * time.Millisecond):
				}
			}
			if interrupt {
				if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			} else {
				start := time.Now()
				// The second process must fail without removing the first one's
				// stage or lock; inspect cleanup only after the owner completes.
				if secondOutput, err := f.command().CombinedOutput(); err == nil || !bytes.Contains(secondOutput, []byte("holds .install.lock")) {
					t.Fatalf("concurrent installer: %v\n%s", err, secondOutput)
				}
				if time.Since(start) > 2*time.Second {
					t.Fatal("concurrent installer did not fail promptly")
				}
				if _, err := os.Stat(filepath.Join(f.prefix, "lib", "debuglet", ".install.lock")); err != nil {
					t.Fatalf("second process removed the first lock: %v", err)
				}
				installerWrite(t, release, nil, 0600)
			}
			select {
			case err := <-done:
				joined = true
				if (err == nil) == interrupt {
					t.Fatalf("installer result after barrier: %v\n%s", err, &output)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("installer did not terminate after barrier")
			}
			f.assertTemporaryCleanup()
			if interrupt {
				f.assertNoPublishedVersion()
			} else {
				f.assertInstalled()
			}
		})
	}
}

func installerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
