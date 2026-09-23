//go:build linux && roles_integration

package roles

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/acceptance/procinventory"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

const hello = "Hello from Debuglet!\n"

// TestInstalledRoles runs the installed commands with independent server,
// executor and client configuration. No source binary replaces the package.
func TestInstalledRoles(t *testing.T) {
	root, source, evidence := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT"), os.Getenv("DEBUGLET_LOCAL_SOURCE_ROOT"), os.Getenv("DEBUGLET_ROLE_EVIDENCE_DIR")
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
		LastRun    string `json:"last_run"`
		Passed     bool   `json:"passed"`
	}{SourceSHA: assets.Manifest.SourceSHA}
	t.Cleanup(func() {
		report.Passed = !t.Failed()
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(evidence, "result.json"), append(data, '\n'), 0600)
		}
		if err != nil {
			t.Error("write role evidence:", err)
		}
	})
	work, err := os.MkdirTemp(evidence, "roles-")
	if err != nil {
		t.Fatal(err)
	}
	var running []*role
	t.Cleanup(func() {
		joined := true
		for i := len(running) - 1; i >= 0; i-- {
			if !running[i].stopped {
				if err := running[i].stop(); err != nil {
					t.Error("role cleanup:", err)
				}
			}
			joined = joined && running[i].clean
		}
		if joined {
			if err := os.RemoveAll(work); err != nil {
				t.Error(err)
			}
		} else {
			t.Log("preserving role state after incomplete cleanup")
		}
	})
	clientDir := filepath.Join(work, "client")
	if err := os.Mkdir(clientDir, 0700); err != nil {
		t.Fatal(err)
	}
	clientConfig := filepath.Join(clientDir, "config.json")
	cli := func(config string, args ...string) []byte {
		t.Helper()
		phase, done := context.WithTimeout(ctx, 30*time.Second)
		defer done()
		args = append([]string{"--config", config, "--output", "json"}, args...)
		out, diagnostics, err := runCommand(phase, assets.CLI, work, isolatedEnvironment(work), args...)
		if err != nil {
			t.Fatalf("CLI %s: %v; stdout=%q stderr=%q", args[4], err, out, diagnostics)
		}
		return out
	}
	start := func(kind, name, endpoint string) *role {
		t.Helper()
		config := filepath.Join(work, kind+"-"+name+"-config.json")
		state := filepath.Join(work, kind+"-"+name)
		args := []string{"--config", config, "--output", "json", kind, "up", "--name", name, "--state-dir", state}
		if kind == "dispatcher" {
			args = append(args, "--port", "0", "--grpc-port", "0")
		} else {
			args = append(args, "--dispatcher", endpoint)
		}
		r, err := startRole(assets, work, kind, name, state, args)
		if err != nil {
			t.Fatal(err)
		}
		running = append(running, r)
		phase, done := context.WithTimeout(ctx, 30*time.Second)
		defer done()
		if err := r.ready(phase); err != nil {
			_, diag, _ := r.output.snapshot()
			t.Fatalf("%s startup: %v; stderr=%q", kind, err, diag)
		}
		return r
	}
	connect := func(endpoint string) {
		t.Helper()
		var saved profile
		if err := decode(cli(clientConfig, "connect", endpoint, "--name", "saved"), &saved); err != nil || saved.Name != "saved" || saved.Endpoint != endpoint || saved.GRPCAddress == "" || saved.YamuxAddress == "" {
			t.Fatalf("connect did not save discovered addresses: %+v, %v", saved, err)
		}
		// A separate client stores a connection, not either daemon's state.
		entries, err := os.ReadDir(clientDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasSuffix(entry.Name(), ".sqlite") || strings.HasSuffix(entry.Name(), ".toml") {
				t.Fatal("client configuration created daemon state")
			}
		}
	}
	nodes := func() []client.Node {
		t.Helper()
		var result []client.Node
		if err := decode(cli(clientConfig, "executor", "list"), &result); err != nil {
			t.Fatal("executor list:", err)
		}
		return result
	}
	submit := func(executor, argument string, fromFile bool) string {
		t.Helper()
		args := []string{"run", "--wait"}
		if fromFile {
			args = append(args, "--wasm", filepath.Join(root, "share", "debuglet", "hello.wasm"))
		} else {
			args = append(args, "--sample", "hello")
		}
		if executor != "" {
			args = append(args, "--executor", executor)
		}
		args = append(args, "--", argument)
		var receipt struct {
			ID            string `json:"id"`
			TransactionID string `json:"transaction_id"`
			ExecutorID    string `json:"executor_id"`
			State         string `json:"state"`
			Error         string `json:"error"`
		}
		if err := decode(cli(clientConfig, args...), &receipt); err != nil {
			t.Fatal("run receipt:", err)
		}
		if !validID(receipt.ID) || !validID(receipt.ExecutorID) || receipt.State != client.StateExited || receipt.Error != "" || executor != "" && receipt.ExecutorID != executor {
			t.Fatalf("unsuccessful run receipt: %+v", receipt)
		}
		return receipt.ID
	}
	stop := func(r *role) {
		t.Helper()
		if err := r.stop(); err != nil {
			t.Fatalf("stop %s: %v", r.kind, err)
		}
	}

	d := start("dispatcher", "local", "")
	connect(d.record.Endpoint)
	if len(nodes()) != 0 {
		t.Fatal("dispatcher-only startup unexpectedly created an executor")
	}
	// Listing known connections is a local config operation, not fleet discovery.
	var listed struct {
		SchemaVersion int       `json:"schema_version"`
		Current       string    `json:"current"`
		Dispatchers   []profile `json:"dispatchers"`
	}
	if err := decode(cli(clientConfig, "dispatcher", "list"), &listed); err != nil || listed.SchemaVersion != 1 || listed.Current != "saved" || len(listed.Dispatchers) != 1 || listed.Dispatchers[0].Name != "saved" || listed.Dispatchers[0].Endpoint != d.record.Endpoint {
		t.Fatalf("saved dispatcher list: %+v, %v", listed, err)
	}
	cli(clientConfig, "dispatcher", "use", "saved")
	e := start("executor", "worker", d.record.Endpoint)
	if e.record.Endpoint != d.record.Endpoint {
		t.Fatal("executor joined a different dispatcher")
	}
	listedNodes := nodes()
	if len(listedNodes) != 1 || !listedNodes[0].Ready || listedNodes[0].ID != e.record.ExecutorID {
		t.Fatalf("executor registration: %+v", listedNodes)
	}
	report.ExecutorID = e.record.ExecutorID
	c := sdk(t, d.record.Endpoint)
	first := submit("", "first-role", false)
	report.FirstRun = first
	original := awaitOutput(t, ctx, c, first, hello+"first-role\n")
	assertCLILogs(t, cli(clientConfig, "logs", first), original)

	goPath := os.Getenv("GO")
	if goPath == "" {
		goPath = "go"
	}
	goPath, err = exec.LookPath(goPath)
	if err != nil {
		t.Fatal(err)
	}
	phase, done := context.WithTimeout(ctx, 45*time.Second)
	out, diag, err := runCommand(phase, goPath, source, os.Environ(), "run", "-mod=readonly", "./examples/client", "--endpoint", d.record.Endpoint, "--wasm", filepath.Join(root, "share", "debuglet", "hello.wasm"))
	done()
	if err != nil || !bytes.Contains(out, []byte(hello)) {
		t.Fatalf("SDK example: %v; stdout=%q stderr=%q", err, out, diag)
	}

	second := start("executor", "second", d.record.Endpoint)
	listedNodes = nodes()
	if len(listedNodes) != 2 || !listedNodes[0].Ready || !listedNodes[1].Ready || second.record.ExecutorID == e.record.ExecutorID {
		t.Fatalf("two distinct ready executors: %+v", listedNodes)
	}
	phase, done = context.WithTimeout(ctx, 10*time.Second)
	out, diag, err = runCommand(phase, assets.CLI, work, isolatedEnvironment(work), "--config", clientConfig, "--output", "json", "run", "--sample", "hello", "--wait")
	done()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(out) != 0 || !bytes.Contains(diag, []byte("more than one executor")) {
		t.Fatalf("ambiguous auto selection did not fail before submission: %v; stdout=%q stderr=%q", err, out, diag)
	}
	explicit := submit(second.record.ExecutorID, "explicit-worker", false)
	awaitOutput(t, ctx, c, explicit, hello+"explicit-worker\n")
	stop(second)
	assertAlive(t, d, e)
	awaitNodes(t, ctx, c, e.record.ExecutorID)
	fileRun := submit("", "file-guest", true)
	awaitOutput(t, ctx, c, fileRun, hello+"file-guest\n")
	stop(e)
	assertAlive(t, d)
	assertStatus(t, ctx, c, first, e.record.ExecutorID)
	stop(d)

	d = start("dispatcher", "local", "")
	connect(d.record.Endpoint)
	e = start("executor", "worker", d.record.Endpoint)
	if e.record.ExecutorID != report.ExecutorID {
		t.Fatal("same-state restart changed executor identity")
	}
	c = sdk(t, d.record.Endpoint)
	assertStatus(t, ctx, c, first, e.record.ExecutorID)
	retained := awaitOutput(t, ctx, c, first, hello+"first-role\n")
	if !bytes.Equal(retained, original) {
		t.Fatal("restart changed stored output")
	}
	assertCLILogs(t, cli(clientConfig, "logs", first), retained)
	last := submit("", "after-restart", false)
	if last == first {
		t.Fatal("restart reused a run UUID")
	}
	report.LastRun = last
	awaitOutput(t, ctx, c, last, hello+"after-restart\n")
	stop(e)
	stop(d)
	t.Log("installed independent roles, pasted-URL client, SDK, executor selection, retained results and joined cleanup passed")
}

type readyRecord struct {
	State        string `json:"state"`
	Role         string `json:"role"`
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	GRPCAddress  string `json:"grpc_address,omitempty"`
	YamuxAddress string `json:"yamux_address,omitempty"`
	ExecutorID   string `json:"executor_id,omitempty"`
	StateDir     string `json:"state_dir"`
}

type profile struct {
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	GRPCAddress  string `json:"grpc_address"`
	YamuxAddress string `json:"yamux_address"`
}

type role struct {
	child                         *demo.Child
	output                        *capture
	kind, name, state, executable string
	record                        readyRecord
	owned                         map[int]procinventory.Process
	stopped, clean                bool
}

func startRole(assets demo.Assets, work, kind, name, state string, args []string) (*role, error) {
	out := new(capture)
	child, err := demo.StartChild(demo.ChildSpec{Path: assets.CLI, Dir: work, Args: args, Env: isolatedEnvironment(work), Stdout: captureWriter{out, true}, Stderr: captureWriter{out, false}})
	if err != nil {
		return nil, err
	}
	executable := assets.Dispatcher
	if kind == "executor" {
		executable = assets.Executor
	}
	return &role{child: child, output: out, kind: kind, name: name, state: state, executable: executable, owned: make(map[int]procinventory.Process)}, nil
}

func (r *role) ready(ctx context.Context) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := r.observeChildren(); err != nil {
			return err
		}
		out, _, overflow := r.output.snapshot()
		if overflow {
			return errors.New("role startup exceeded output bound")
		}
		if bytes.Contains(out, []byte{'\n'}) {
			if err := decode(out, &r.record); err != nil {
				return err
			}
			u, err := url.Parse(r.record.Endpoint)
			if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || r.record.State != "ready" || r.record.Role != r.kind || r.record.Name != r.name || r.record.StateDir != r.state {
				return errors.New("invalid role readiness")
			}
			if r.kind == "executor" && !validID(r.record.ExecutorID) {
				return errors.New("invalid ready executor identity")
			}
			if r.kind == "dispatcher" && (r.record.GRPCAddress == "" || r.record.YamuxAddress != u.Host) {
				return errors.New("missing dispatcher control addresses")
			}
			if len(r.owned) > 1 {
				return errors.New("role started more than one daemon")
			}
			if len(r.owned) == 1 {
				data, err := readRegular(filepath.Join(r.state, "ready.json"), 4096)
				if err != nil {
					return err
				}
				var saved readyRecord
				if decode(data, &saved) != nil || saved != r.record {
					return errors.New("saved role readiness differs from stdout")
				}
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.child.Done():
			return fmt.Errorf("role exited during startup: %w", r.child.Wait(ctx))
		case <-ticker.C:
		}
	}
}

func (r *role) stop() error {
	if r.stopped {
		if r.clean {
			return nil
		}
		return errors.New("previous role cleanup failed")
	}
	r.stopped = true
	ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	var result error
	select {
	case <-r.child.Done():
		result = errors.New("role exited before requested stop")
	default:
		result = syscall.Kill(r.child.PID(), syscall.SIGINT)
	}
	result = errors.Join(result, r.child.Wait(ctx))
	cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
	result = errors.Join(result, r.child.Stop(cleanup))
	end()
	if !r.child.CleanupComplete() {
		result = errors.Join(result, errors.New("role CLI cleanup incomplete"))
	}
	for _, p := range r.owned {
		if alive(p) || !errors.Is(syscall.Kill(-p.Group, 0), syscall.ESRCH) {
			result = errors.Join(result, errors.New("owned daemon remains after role joined"))
			if alive(p) {
				_ = syscall.Kill(p.PID, syscall.SIGKILL)
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(r.state, "ready.json")); !os.IsNotExist(err) {
		result = errors.Join(result, errors.New("role readiness remains after stop"))
	}
	if r.record.State != "" {
		data, _, overflow := r.output.snapshot()
		var final readyRecord
		if overflow || decode(data, &final) != nil || final != r.record {
			result = errors.Join(result, errors.New("role did not emit exactly one readiness document"))
		}
		if r.kind == "dispatcher" {
			for _, address := range []string{r.record.YamuxAddress, r.record.GRPCAddress} {
				conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
				if err == nil {
					conn.Close()
					result = errors.Join(result, errors.New("dispatcher listener remains after stop"))
				}
			}
		}
	}
	r.clean = result == nil
	return result
}

func assertAlive(t *testing.T, roles ...*role) {
	t.Helper()
	for _, r := range roles {
		select {
		case <-r.child.Done():
			t.Fatalf("stopping another role also stopped %s", r.kind)
		default:
		}
		for _, p := range r.owned {
			if !alive(p) {
				t.Fatalf("independent %s daemon disappeared", r.kind)
			}
		}
	}
}

func assertStatus(t *testing.T, ctx context.Context, c *client.Client, id, executor string) {
	t.Helper()
	state, err := c.Status(ctx, id)
	if err != nil || state.State != client.StateExited || state.Error != "" || state.ExecutorID != executor {
		t.Fatalf("stored status: %+v, %v", state, err)
	}
}

func assertCLILogs(t *testing.T, out, expected []byte) {
	t.Helper()
	var page client.LogPage
	if err := decode(out, &page); err != nil {
		t.Fatal("CLI logs:", err)
	}
	var data []byte
	for _, entry := range page.Logs {
		data = append(data, entry.Output...)
	}
	if page.State != client.StateExited || page.Error != "" || page.HasMore || !bytes.Equal(data, expected) {
		t.Fatalf("CLI logs differ from stored output: %+v", page)
	}
}

func awaitNodes(t *testing.T, ctx context.Context, c *client.Client, id string) {
	t.Helper()
	phase, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		nodes, err := c.Nodes(phase)
		if err != nil {
			t.Fatal(err)
		}
		ready := []string{}
		for _, n := range nodes {
			if n.Ready {
				ready = append(ready, n.ID)
			}
		}
		if len(ready) == 1 && ready[0] == id {
			return
		}
		select {
		case <-phase.Done():
			t.Fatal("remaining executor not ready:", phase.Err())
		case <-ticker.C:
		}
	}
}
