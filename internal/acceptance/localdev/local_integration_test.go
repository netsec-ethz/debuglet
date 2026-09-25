//go:build linux && localdev_integration

package localdev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/acceptance/procinventory"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

const hello = "Hello from Debuglet!\n"

// TestLocalDevelopment exercises the commands shipped in the installed
// package. Missing assets fail rather than silently removing this CI gate.
func TestLocalDevelopment(t *testing.T) {
	root, source, evidence := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT"), os.Getenv("DEBUGLET_LOCAL_SOURCE_ROOT"), os.Getenv("DEBUGLET_LOCAL_EVIDENCE_DIR")
	if !filepath.IsAbs(root) || !filepath.IsAbs(source) || !filepath.IsAbs(evidence) {
		t.Fatal("absolute installed, source and evidence directories are required")
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatalf("installed/source identity: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	report := struct {
		SourceSHA  string `json:"source_sha"`
		ExecutorID string `json:"executor_id"`
		FirstRun   string `json:"first_run"`
		SecondRun  string `json:"second_run"`
		Passed     bool   `json:"passed"`
	}{SourceSHA: assets.Manifest.SourceSHA}
	t.Cleanup(func() {
		report.Passed = !t.Failed()
		b, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(evidence, "result.json"), append(b, '\n'), 0600)
		}
		if err != nil {
			t.Error("write local development evidence:", err)
		}
	})
	work, err := os.MkdirTemp(evidence, "local-")
	if err != nil {
		t.Fatal(err)
	}
	var sessions []*environment
	t.Cleanup(func() {
		joined := true
		for _, s := range sessions {
			if !s.stopped {
				if err := s.stop(); err != nil {
					t.Error("cleanup local environment:", err)
					joined = false
				}
			}
			if !s.clean {
				joined = false
			}
		}
		if joined {
			if err := os.RemoveAll(work); err != nil {
				t.Error(err)
			}
		} else {
			t.Log("incomplete cleanup: preserving owned state for inspection")
		}
	})
	state := filepath.Join(work, "state")
	start := func() *environment {
		t.Helper()
		s, err := startEnvironment(assets.CLI, work, state)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, s)
		startup, done := context.WithTimeout(ctx, 20*time.Second)
		defer done()
		if err := s.ready(startup, assets); err != nil {
			t.Fatalf("local startup: %v", err)
		}
		if s.record.StateDir != state {
			t.Fatal("ready record changed the requested state directory")
		}
		data, err := readRegular(filepath.Join(state, "environment.json"), 4096)
		if err != nil {
			t.Fatal("live environment record:", err)
		}
		var saved readyRecord
		if decode(data, &saved) != nil || saved != s.record {
			t.Fatal("live environment record differs from stdout readiness")
		}
		return s
	}
	first := start()
	report.ExecutorID = first.record.ExecutorID
	one := runHello(t, ctx, assets.CLI, work, first.record, "first-run")
	report.FirstRun = one
	firstClient := sdk(t, first.record.Endpoint)
	original := awaitOutput(t, ctx, firstClient, one, hello+"first-run\n")

	// Exercise the documented standalone SDK consumer against the actual API.
	goPath := os.Getenv("GO")
	if goPath == "" {
		goPath = "go"
	}
	goPath, err = exec.LookPath(goPath)
	if err != nil {
		t.Fatal(err)
	}
	exampleCtx, exampleDone := context.WithTimeout(ctx, 45*time.Second)
	out, err := runCommand(exampleCtx, goPath, source, os.Environ(), "run", "-mod=readonly", "./examples/client", "--endpoint", first.record.Endpoint, "--wasm", filepath.Join(root, "share", "debuglet", "hello.wasm"))
	exampleDone()
	if err != nil || !bytes.Contains(out, []byte(hello)) {
		t.Fatalf("standalone SDK example: %v; output=%q", err, out)
	}
	if err := first.stop(); err != nil {
		t.Fatal("first graceful stop:", err)
	}
	second := start()
	if second.record.ExecutorID != first.record.ExecutorID {
		t.Fatal("restart changed the retained executor identity")
	}
	secondClient := sdk(t, second.record.Endpoint)
	status, err := secondClient.Status(ctx, one)
	if err != nil || status.State != client.StateExited || status.Error != "" || status.ExecutorID != first.record.ExecutorID {
		t.Fatalf("retained result: %+v, %v", status, err)
	}
	retained := awaitOutput(t, ctx, secondClient, one, hello+"first-run\n")
	if !bytes.Equal(original, retained) {
		t.Fatal("restart changed the first run's output")
	}
	two := runHello(t, ctx, assets.CLI, work, second.record, "second-run")
	if two == one {
		t.Fatal("second submission reused the first run ID")
	}
	report.SecondRun = two
	awaitOutput(t, ctx, secondClient, two, hello+"second-run\n")
	if err := second.stop(); err != nil {
		t.Fatal("second graceful stop:", err)
	}
	t.Log("installed CLI hello, standalone SDK example, retained result/output and second run passed with joined cleanup")
}

type readyRecord struct {
	State      string `json:"state"`
	Endpoint   string `json:"endpoint"`
	ExecutorID string `json:"executor_id"`
	StateDir   string `json:"state_dir"`
}

type environment struct {
	child   *demo.Child
	output  *capture
	record  readyRecord
	state   string
	owned   map[int]procinventory.Process
	stopped bool
	clean   bool
}

func startEnvironment(cli, work, state string) (*environment, error) {
	out := new(capture)
	child, err := demo.StartChild(demo.ChildSpec{Path: cli, Dir: work, Args: []string{"--output", "json", "up", "--state-dir", state, "--port", "0"}, Env: []string{"LANG=C", "LC_ALL=C", "TZ=UTC", "TMPDIR=" + work}, Stdout: captureWriter{out, true}, Stderr: captureWriter{out, false}})
	if err != nil {
		return nil, err
	}
	return &environment{child: child, output: out, state: state, owned: map[int]procinventory.Process{}}, nil
}

func (s *environment) ready(ctx context.Context, assets demo.Assets) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := s.observeChildren(assets); err != nil {
			return err
		}
		data, overflow := s.output.bytes()
		if overflow {
			return errors.New("local startup exceeded diagnostic bound")
		}
		if bytes.Contains(data, []byte{'\n'}) {
			if err := decode(data, &s.record); err != nil {
				return err
			}
			u, err := url.Parse(s.record.Endpoint)
			if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || s.record.State != "ready" || !validID(s.record.ExecutorID) || len(s.owned) > 2 {
				return errors.New("invalid readiness or unexpected daemon children")
			}
			// Readiness can be written after this poll's child snapshot. Wait
			// for independent process observation instead of rejecting that race.
			if len(s.owned) == 2 {
				c, err := client.New(s.record.Endpoint, client.Options{})
				if err != nil {
					return err
				}
				nodes, err := c.Nodes(ctx)
				if err != nil || len(nodes) != 1 || !nodes[0].Ready || nodes[0].ID != s.record.ExecutorID {
					return errors.New("ready environment does not expose its executor")
				}
				return nil
			}
		}
		select {
		case <-s.child.Done():
			return fmt.Errorf("up exited before readiness: %w", s.child.Wait(ctx))
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *environment) stop() error {
	if s.stopped {
		if !s.clean {
			return errors.New("earlier local cleanup was incomplete")
		}
		return nil
	}
	s.stopped = true
	ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	var result error
	select {
	case <-s.child.Done():
		result = errors.New("up exited before the requested stop")
	default:
		result = syscall.Kill(s.child.PID(), syscall.SIGINT)
	}
	result = errors.Join(result, s.child.Wait(ctx))
	// Stop joins/cache-checks the already exited CLI group. On a failed Wait it
	// performs bounded emergency teardown; that failure remains in result.
	cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
	result = errors.Join(result, s.child.Stop(cleanup))
	end()
	if !s.child.CleanupComplete() {
		result = errors.Join(result, errors.New("up process group remains"))
	}
	for _, p := range s.owned {
		if alive(p) || !errors.Is(syscall.Kill(-p.Group, 0), syscall.ESRCH) {
			result = errors.Join(result, errors.New("owned daemon process/group remains after up joined"))
			// Repair only an independently observed, still-matching child. This
			// never makes the preceding failure a successful cleanup result.
			if alive(p) {
				_ = syscall.Kill(p.PID, syscall.SIGKILL)
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(s.state, "environment.json")); !os.IsNotExist(err) {
		result = errors.Join(result, errors.New("live environment record remains after stop"))
	}
	if s.record.Endpoint != "" {
		data, overflow := s.output.bytes()
		var final readyRecord
		if overflow || decode(data, &final) != nil || final != s.record {
			result = errors.Join(result, errors.New("up did not emit exactly one bounded readiness document"))
		}
		u, _ := url.Parse(s.record.Endpoint)
		conn, err := net.DialTimeout("tcp", u.Host, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			result = errors.Join(result, errors.New("local API listener remains after stop"))
		}
	}
	s.clean = result == nil
	return result
}

func sdk(t *testing.T, endpoint string) *client.Client {
	t.Helper()
	c, err := client.New(endpoint, client.Options{RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func runHello(t *testing.T, ctx context.Context, cli, work string, ready readyRecord, argument string) string {
	t.Helper()
	phase, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	out, err := runCommand(phase, cli, work, []string{"LANG=C", "LC_ALL=C", "TZ=UTC"}, "--endpoint", ready.Endpoint, "--timeout", "25s", "--output", "json", "run", "--sample", "hello", "--executor", "auto", "--wait", "--", argument)
	var receipt struct {
		ID            string `json:"id"`
		TransactionID string `json:"transaction_id"`
		ExecutorID    string `json:"executor_id"`
		State         string `json:"state"`
		Error         string `json:"error"`
	}
	if err != nil || decode(out, &receipt) != nil || !validID(receipt.ID) || receipt.ExecutorID != ready.ExecutorID || receipt.State != client.StateExited || receipt.Error != "" {
		t.Fatalf("installed sample run: %v; receipt=%q", err, out)
	}
	return receipt.ID
}

func awaitOutput(t *testing.T, ctx context.Context, c *client.Client, id, want string) []byte {
	t.Helper()
	phase, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	var output []byte
	var after int64
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		page, err := c.Logs(phase, id, client.LogOptions{After: after, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		last := after
		for _, entry := range page.Logs {
			if entry.ID <= last || len(output)+len(entry.Output) > 64<<10 {
				t.Fatal("invalid or excessive sample output")
			}
			last = entry.ID
			output = append(output, entry.Output...)
		}
		if page.After != last || page.HasMore && len(page.Logs) == 0 {
			t.Fatal("invalid sample output cursor")
		}
		after = last
		if page.State == client.StateExited && page.Error == "" && !page.HasMore && string(output) == want {
			return output
		}
		if page.Error != "" {
			t.Fatal("sample failed:", page.Error)
		}
		if page.HasMore {
			continue
		}
		select {
		case <-phase.Done():
			t.Fatalf("sample output did not arrive: %v; output=%q", phase.Err(), output)
		case <-ticker.C:
		}
	}
}

func runCommand(ctx context.Context, path, dir string, env []string, args ...string) ([]byte, error) {
	out := new(capture)
	child, err := demo.StartChild(demo.ChildSpec{Path: path, Dir: dir, Args: args, Env: env, Stdout: captureWriter{out, true}, Stderr: captureWriter{out, false}})
	if err != nil {
		return nil, err
	}
	err = child.Wait(ctx)
	cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
	err = errors.Join(err, child.Stop(cleanup))
	done()
	if !child.CleanupComplete() {
		err = errors.Join(err, errors.New("command cleanup incomplete"))
	}
	data, overflow := out.bytes()
	if overflow {
		err = errors.Join(err, errors.New("command output exceeded bound"))
	}
	return data, err
}

type capture struct {
	mu       sync.Mutex
	stdout   bytes.Buffer
	used     int
	overflow bool
}
type captureWriter struct {
	c      *capture
	stdout bool
}

func (w captureWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	n := len(p)
	if left := (1 << 20) - w.c.used; len(p) > left {
		p = p[:left]
		w.c.overflow = true
	}
	w.c.used += len(p)
	if w.stdout {
		w.c.stdout.Write(p)
	}
	return n, nil
}
func (c *capture) bytes() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.stdout.Bytes()), c.overflow
}
func decode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}
func validID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}
func readRegular(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, errors.New("file exceeds bound")
	}
	return data, err
}

// A daemon reparented after an unexpected supervisor exit keeps the identity
// this harness independently established for it.
func alive(p procinventory.Process) bool {
	current, err := procinventory.Read(p.PID)
	return err == nil && procinventory.Same(p, current) && procinventory.Live(current)
}
func (s *environment) observeChildren(assets demo.Assets) error {
	children, err := procinventory.Descendants(s.child.PID())
	if err != nil {
		return err
	}
	for _, pid := range children {
		p, err := procinventory.Read(pid)
		if err != nil {
			continue // A fork/exit transition is not signal authority.
		}
		if p.Parent != s.child.PID() || p.Group != p.PID || p.Executable != assets.Dispatcher && p.Executable != assets.Executor {
			continue
		}
		if previous, ok := s.owned[pid]; ok && !procinventory.Same(previous, p) {
			return errors.New("owned child identity changed")
		}
		s.owned[pid] = p
	}
	return nil
}
