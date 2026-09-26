// Command packaging builds and packages a Linux candidate. It is a
// repository tool, never shipped or required by the installed runtime.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/artifact"
)

type buildRecord struct {
	Metadata artifact.Manifest        `json:"metadata"`
	Compiled map[string]artifact.File `json:"compiled_files"`
}

var targets = map[string]string{
	"debuglet-dispatcher": "./cmd/dispatcher", "debuglet-executor": "./cmd/executor", "dbl": "./cmd/dbl",
	"helloworld.wasm": "./examples/debuglets/go/helloworld", "ping.wasm": "./examples/debuglets/go/ping", "demo.wasm": "./examples/debuglets/go/demo",
	"hello.wasm": "./examples/debuglets/go/hello-local",
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "packaging:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("expected build, package, verify, check-demo-evidence or check-compatibility-evidence")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dist := fs.String("dist", ".cache/ci/dist", "compiled artifacts")
	out := fs.String("out", ".cache/ci/packages", "candidate output")
	installed := fs.String("installed-root", "", "installed version directory")
	evidence := fs.String("evidence", "", "Go JSON evidence file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	sha, err := cleanRevision(ctx)
	if err != nil {
		return err
	}
	switch args[0] {
	case "build":
		return build(ctx, *dist, sha)
	case "package":
		return packWithCopy(*dist, *out, sha, copyFile)
	case "verify":
		return verifyInstalled(ctx, *installed, sha)
	case "check-demo-evidence":
		return checkDemoEvidence(*evidence)
	case "check-compatibility-evidence":
		return checkTestEvidence(*evidence, "github.com/netsec-ethz/debuglet/internal/acceptance/canary", "TestCanaryLocal")
	case "check-local-evidence":
		return checkTestEvidence(*evidence, "github.com/netsec-ethz/debuglet/internal/acceptance/localdev", "TestLocalDevelopment")
	case "check-role-evidence":
		return checkTestEvidence(*evidence, "github.com/netsec-ethz/debuglet/internal/acceptance/roles", "TestInstalledRoles")
	case "check-guest-abi-evidence":
		return checkTestEvidence(*evidence, "github.com/netsec-ethz/debuglet/pkg/debuglet", "TestGuestABIInstalledGuests")
	default:
		return errors.New("expected build, package, verify, check-demo-evidence or check-compatibility-evidence")
	}
}
func command(ctx context.Context, name string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.WaitDelay = 2 * time.Second
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
func cleanRevision(ctx context.Context) (string, error) {
	status, err := command(ctx, "git", "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return "", err
	}
	if status != "" {
		return "", errors.New("candidate builds require a clean committed checkout")
	}
	sha, err := command(ctx, "git", "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	if !artifact.ValidSourceSHA(sha) {
		return "", errors.New("invalid source revision")
	}
	return sha, nil
}
func candidateVersion(ctx context.Context, sha string) (string, error) {
	tag := os.Getenv("CI_COMMIT_TAG")
	if tag == "" {
		return "v0.0.0-dev." + sha[:12], nil
	}
	if !artifact.ValidVersion(tag) || os.Getenv("CI_COMMIT_REF_PROTECTED") != "true" {
		return "", errors.New("release versions require a valid protected tag")
	}
	tagged, err := command(ctx, "git", "rev-parse", "refs/tags/"+tag+"^{commit}")
	if err != nil {
		return "", err
	}
	if tagged != sha {
		return "", errors.New("release tag does not identify this checkout")
	}
	return tag, nil
}
func orderedKeys[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
func realDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("output is not a real directory: %s", path)
	}
	return nil
}
func build(ctx context.Context, dist, sha string) error {
	if runtime.Version() != artifact.Toolchain || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("build requires pinned Go 1.25.11 on Linux amd64")
	}
	version, err := candidateVersion(ctx, sha)
	if err != nil {
		return err
	}
	if err := realDirectory(dist); err != nil {
		return err
	}
	entries, err := os.ReadDir(dist)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, ok := targets[entry.Name()]; !ok && entry.Name() != "build-record.json" {
			return fmt.Errorf("unexpected build output: %s", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("existing build outputs must be regular files")
		}
	}
	if err := os.Remove(filepath.Join(dist, "build-record.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	meta := artifact.Manifest{SchemaVersion: 1, Version: version, SourceSHA: sha, GoVersion: runtime.Version(), GOOS: "linux", GOARCH: "amd64", GuestABI: artifact.GuestABI, Files: map[string]artifact.File{}, BuildPipelineURL: os.Getenv("CI_PIPELINE_URL")}
	record := buildRecord{Metadata: meta, Compiled: map[string]artifact.File{}}
	goCommand := os.Getenv("GO")
	if goCommand == "" {
		goCommand = "go"
	}
	if err := verifyCompiler(ctx, goCommand); err != nil {
		return err
	}
	ldflags := "-X github.com/netsec-ethz/debuglet/internal/buildinfo.Version=" + version + " -X github.com/netsec-ethz/debuglet/internal/buildinfo.Revision=" + sha + " -X github.com/netsec-ethz/debuglet/internal/buildinfo.GuestABI=" + artifact.GuestABI
	for _, name := range orderedKeys(targets) {
		targetOS, targetArch := "linux", "amd64"
		stamp := []string{"-ldflags", ldflags}
		if strings.HasSuffix(name, ".wasm") {
			// Guest samples carry no candidate identity, so their bytes depend only on the guest source and toolchain.
			targetOS, targetArch, stamp = "wasip1", "wasm", []string{"-buildvcs=false"}
		}
		args := append([]string{"build", "-mod=readonly", "-trimpath"}, stamp...)
		c := exec.CommandContext(ctx, goCommand, append(args, "-o", filepath.Join(dist, name), targets[name])...)
		c.WaitDelay = 2 * time.Second
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+targetOS, "GOARCH="+targetArch, "GOTOOLCHAIN=local")
		if err := c.Run(); err != nil {
			return fmt.Errorf("build %s: %w", name, err)
		}
		if targetOS == "linux" {
			info, err := buildinfo.ReadFile(filepath.Join(dist, name))
			if err != nil {
				return fmt.Errorf("read compiled identity: %w", err)
			}
			if info.GoVersion != artifact.Toolchain {
				return errors.New("compiled binary toolchain differs from pinned identity")
			}
		}
		f, err := artifact.HashFile(filepath.Join(dist, name))
		if err != nil {
			return err
		}
		record.Compiled[name] = f
	}
	return writeJSON(filepath.Join(dist, "build-record.json"), record)
}
func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Chmod(path, 0644)
}
func loadRecord(dist, sha string) (buildRecord, error) {
	var record buildRecord
	data, err := readBuildRecord(filepath.Join(dist, "build-record.json"))
	if err != nil {
		return record, err
	}
	if len(data) > 64*1024 {
		return record, errors.New("build record too large")
	}
	if err := artifact.CheckUniqueJSON(data); err != nil {
		return record, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return record, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return record, errors.New("trailing build record data")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return record, err
	}
	if len(raw) != 2 || raw["metadata"] == nil || raw["compiled_files"] == nil {
		return record, errors.New("build record requires exact metadata and compiled_files keys")
	}
	var compiledFields map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw["compiled_files"], &compiledFields); err != nil || compiledFields == nil {
		return record, errors.New("compiled_files must be an object")
	}
	for _, fields := range compiledFields {
		if len(fields) != 2 || fields["sha256"] == nil || fields["bytes"] == nil {
			return record, errors.New("compiled file records require exact sha256 and bytes keys")
		}
	}
	metadata, err := artifact.DecodeManifestMetadata(raw["metadata"])
	if err != nil {
		return record, err
	}
	record.Metadata = metadata
	m := record.Metadata
	if m.SchemaVersion != 1 || m.SourceSHA != sha || m.Dirty || !artifact.ValidVersion(m.Version) || m.GoVersion != artifact.Toolchain || m.GOOS != "linux" || m.GOARCH != "amd64" || m.GuestABI != artifact.GuestABI || len(m.Files) != 0 {
		return record, errors.New("build record identity does not match this candidate")
	}
	if len(record.Compiled) != len(targets) {
		return record, errors.New("build record has an unexpected artifact set")
	}
	entries, err := os.ReadDir(dist)
	if err != nil {
		return record, err
	}
	if len(entries) != len(targets)+1 {
		return record, errors.New("build directory has unexpected entries")
	}
	for name := range targets {
		want, ok := record.Compiled[name]
		if !ok {
			return record, errors.New("missing compiled artifact")
		}
		got, err := artifact.HashFile(filepath.Join(dist, name))
		if err != nil {
			return record, err
		}
		if got != want {
			return record, fmt.Errorf("compiled artifact checksum mismatch: %s", name)
		}
	}
	return record, nil
}
func copyFile(source, dest string, mode os.FileMode) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, f)
	closeErr := out.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	return os.Chmod(dest, mode)
}

// packWithCopy takes a copier so a test can change a file after the record check.
func packWithCopy(dist, out, sha string, copyPayload func(string, string, os.FileMode) error) error {
	record, err := loadRecord(dist, sha)
	if err != nil {
		return err
	}
	if err := realDirectory(out); err != nil {
		return err
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("package output directory must be empty")
	}
	stage, err := os.MkdirTemp(filepath.Dir(out), ".package-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	m := record.Metadata
	for _, name := range []string{"dbl", "debuglet-dispatcher", "debuglet-executor"} {
		if err := copyPayload(filepath.Join(dist, name), filepath.Join(stage, "bin", name), 0755); err != nil {
			return err
		}
	}
	for _, name := range []string{"demo.wasm", "hello.wasm"} {
		if err := copyPayload(filepath.Join(dist, name), filepath.Join(stage, "share", "debuglet", name), 0644); err != nil {
			return err
		}
	}
	if err := copyPayload("LICENSE", filepath.Join(stage, "LICENSE"), 0644); err != nil {
		return err
	}
	readme, err := os.ReadFile("README-install.md")
	if err != nil {
		return err
	}
	readme = bytes.ReplaceAll(readme, []byte("@VERSION@"), []byte(m.Version))
	readme = bytes.ReplaceAll(readme, []byte("@SOURCE_SHA@"), []byte(m.SourceSHA))
	if err := os.WriteFile(filepath.Join(stage, "README-install.md"), readme, 0644); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(stage, "README-install.md"), 0644); err != nil {
		return err
	}
	for source, destination := range map[string]string{"dbl": "bin/dbl", "debuglet-dispatcher": "bin/debuglet-dispatcher", "debuglet-executor": "bin/debuglet-executor", "demo.wasm": "share/debuglet/demo.wasm", "hello.wasm": "share/debuglet/hello.wasm"} {
		got, err := artifact.HashFile(filepath.Join(stage, filepath.FromSlash(destination)))
		if err != nil {
			return err
		}
		if got != record.Compiled[source] {
			return fmt.Errorf("compiled artifact changed while packaging: %s", source)
		}
	}
	for name := range artifact.PayloadModes() {
		if name == artifact.ManifestPath {
			continue
		}
		f, err := artifact.HashFile(filepath.Join(stage, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		m.Files[name] = f
	}
	if err := writeJSON(filepath.Join(stage, filepath.FromSlash(artifact.ManifestPath)), m); err != nil {
		return err
	}
	if _, err := artifact.Verify(stage); err != nil {
		return err
	}
	archiveName := "debuglet-" + m.Version + "-linux-amd64.tar.gz"
	archivePath := filepath.Join(out, archiveName)
	if err := archive(stage, archivePath); err != nil {
		return err
	}
	template, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		return err
	}
	var sums strings.Builder
	for _, name := range orderedKeys(artifact.PayloadModes()) {
		f, err := artifact.HashFile(filepath.Join(stage, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s  %s\n", f.SHA256, name)
	}
	installer := bytes.ReplaceAll(template, []byte("@VERSION@"), []byte(m.Version))
	installer = bytes.ReplaceAll(installer, []byte("@SOURCE_SHA@"), []byte(m.SourceSHA))
	installer = bytes.ReplaceAll(installer, []byte("@PAYLOAD_SUMS@"), []byte(strings.TrimSuffix(sums.String(), "\n")))
	if err := os.WriteFile(filepath.Join(out, "install.sh"), installer, 0755); err != nil {
		return err
	}
	var detached strings.Builder
	for _, name := range []string{archiveName, "install.sh"} {
		f, err := artifact.HashFile(filepath.Join(out, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(&detached, "%s  %s\n", f.SHA256, name)
	}
	if err := os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(detached.String()), 0644); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, archivePath)
	return nil
}
func archive(root, path string) (err error) {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(out)
	tarWriter := tar.NewWriter(gzipWriter)
	defer func() { err = errors.Join(err, tarWriter.Close(), gzipWriter.Close(), out.Close()) }()
	modes := artifact.PayloadModes()
	for _, name := range orderedKeys(modes) {
		source := filepath.Join(root, filepath.FromSlash(name))
		info, err := os.Stat(source)
		if err != nil {
			return err
		}
		header := &tar.Header{Name: name, Mode: int64(modes[name]), Size: info.Size(), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		file, err := os.Open(source)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

// verifyInstalled checks the real binary after the installer has verified bytes.
func verifyInstalled(parent context.Context, root, sha string) error {
	m, err := artifact.Verify(root)
	if err != nil {
		return err
	}
	if m.SourceSHA != sha {
		return errors.New("installed candidate does not match this checkout")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var stdout, stderr limitedOutput
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "dbl"), "--output", "json", "version")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installed CLI version: %w: %s", err, stderr.Bytes())
	}
	if stdout.overflow || stderr.overflow {
		return errors.New("installed version output exceeds limit")
	}
	var version struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Revision string `json:"revision"`
		Modified bool   `json:"modified"`
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&version); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing installed version output")
	}
	if version.Module != "github.com/netsec-ethz/debuglet" || version.Version != m.Version || version.Revision != sha || version.Modified {
		return errors.New("installed CLI build identity does not match manifest")
	}
	return json.NewEncoder(os.Stdout).Encode(m)
}

type limitedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 64*1024 - b.Len()
	if n > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

func readBuildRecord(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > 64*1024 {
		return nil, errors.New("build record must be a regular file within 64 KiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("build record changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64*1024 {
		return nil, errors.New("build record exceeds 64 KiB")
	}
	return data, nil
}

func checkDemoEvidence(path string) error {
	return checkTestEvidence(path, "github.com/netsec-ethz/debuglet/internal/demo", "TestInstalledDemoAcceptance")
}

func checkTestEvidence(path, packageName, testName string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	passes := 0
	for {
		var e struct{ Action, Test, Package string }
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if token != json.Delim('{') {
			return errors.New("test evidence event is not an object")
		}
		seen := make(map[string]bool)
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[strings.ToLower(key)] {
				return errors.New("test evidence contains duplicate event fields")
			}
			seen[strings.ToLower(key)] = true
			var value json.RawMessage
			if err := d.Decode(&value); err != nil {
				return err
			}
			var field *string
			switch strings.ToLower(key) {
			case "action":
				if key != "Action" {
					return errors.New("test evidence contains an aliased Action field")
				}
				field = &e.Action
			case "test":
				if key != "Test" {
					return errors.New("test evidence contains an aliased Test field")
				}
				field = &e.Test
			case "package":
				if key != "Package" {
					return errors.New("test evidence contains an aliased Package field")
				}
				field = &e.Package
			}
			if field != nil {
				if bytes.Equal(value, []byte("null")) {
					return errors.New("test evidence contains a null control field")
				}
				if err := json.Unmarshal(value, field); err != nil {
					return err
				}
			}
		}
		if token, err := d.Token(); err != nil || token != json.Delim('}') {
			return errors.New("test evidence contains an incomplete event")
		}
		if e.Action == "fail" || e.Action == "skip" || e.Action == "build-fail" {
			return errors.New("test evidence contains a failure or skip")
		}
		switch e.Action {
		case "start", "run", "pause", "cont", "pass", "bench", "output", "build-output":
		default:
			return errors.New("test evidence contains an invalid event action")
		}
		if e.Action == "pass" && e.Test == testName && e.Package == packageName {
			passes++
		}
	}
	if passes != 1 {
		return fmt.Errorf("expected exactly one %s pass event", testName)
	}
	return nil
}

func verifyCompiler(ctx context.Context, path string) error {
	version, err := command(ctx, path, "version")
	if err != nil {
		return err
	}
	if version != "go version "+artifact.Toolchain+" linux/amd64" {
		return errors.New("selected compiler is not pinned Go 1.25.11 for Linux amd64")
	}
	return nil
}
