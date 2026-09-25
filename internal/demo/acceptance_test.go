//go:build linux && demoacceptance

package demo

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// TestInstalledDemoAcceptance is deliberately opt-in and fail-closed. All
// subprocesses use the verified installed candidate, never go run or a rebuild.
func TestInstalledDemoAcceptance(t *testing.T) {
	root := os.Getenv("DEBUGLET_DEMO_INSTALL_ROOT")
	evidenceDir := os.Getenv("DEBUGLET_DEMO_EVIDENCE_DIR")
	if !filepath.IsAbs(root) || !filepath.IsAbs(evidenceDir) {
		t.Fatal("absolute DEBUGLET_DEMO_INSTALL_ROOT and DEBUGLET_DEMO_EVIDENCE_DIR are required")
	}
	assets, err := ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil {
		t.Fatalf("installed assets: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	sha, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	cancel()
	if err != nil || strings.TrimSpace(string(sha)) != assets.Manifest.SourceSHA {
		t.Fatalf("installed/source revision mismatch: installed=%s source=%q error=%v", assets.Manifest.SourceSHA, sha, err)
	}
	if err := os.MkdirAll(evidenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Exercise the managed symlink as an end user does, in addition to resolving
	// and hashing its real payload above.
	entry := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(root))), "bin", "dbl")
	resolved, err := filepath.EvalSymlinks(entry)
	if err != nil || resolved != assets.CLI {
		t.Fatalf("managed CLI link: %q %v", resolved, err)
	}
	sibling, err := StartChild(ChildSpec{Path: "/bin/sleep", Dir: t.TempDir(), Args: []string{"600"}, Env: []string{}, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sibling.Stop(ctx); err != nil {
			t.Error("join unrelated sibling:", err)
		}
	})
	h := &installedHarness{assets: assets, entry: entry, evidenceDir: evidenceDir, sibling: sibling}
	t.Run("ownership_guards", func(t *testing.T) { h.ownershipGuards(t) })
	t.Run("real_database_wire_and_identity", func(t *testing.T) { h.libraryCase(t, "success") })
	for _, fault := range []string{"executor_start_failure", "dispatcher_early_death", "wrong_reply", "withheld_eof", "diagnostic_overflow"} {
		t.Run(fault, func(t *testing.T) { h.libraryCase(t, fault) })
	}
	var results []Result
	for i := 0; i < 2; i++ {
		t.Run(fmt.Sprintf("installed_cli_%d", i+1), func(t *testing.T) { r := h.cliCase(t, "success"); results = append(results, r) })
	}
	t.Run("concurrent_installed_clis", func(t *testing.T) {
		var wg sync.WaitGroup
		got := make([]Result, 2)
		for i := range got {
			wg.Go(func() { got[i] = h.cliCase(t, fmt.Sprintf("concurrent_%d", i+1)) })
		}
		wg.Wait()
		results = append(results, got...)
		h.mu.Lock()
		one, two := h.intervals["concurrent_1"], h.intervals["concurrent_2"]
		overlap := h.concurrentOverlap
		h.mu.Unlock()
		if !overlap || one.start.IsZero() || two.start.IsZero() || !one.start.Before(two.end) || !two.start.Before(one.end) {
			t.Errorf("real ready CLI intervals did not overlap: first=%+v second=%+v", one, two)
		}
	})
	t.Run("fresh_identities", func(t *testing.T) {
		ids, runs, nonces := map[string]bool{}, map[string]bool{}, map[string]bool{}
		if len(results) != 4 {
			t.Fatalf("expected four completed CLI runs, got %d", len(results))
		}
		for _, r := range results {
			nonce := strings.TrimPrefix(r.Response, "DEBUGLET/1 ")
			if r.ExecutorID == "" || r.RunID == "" || len(nonce) != 32 || ids[r.ExecutorID] || runs[r.RunID] || nonces[nonce] {
				t.Fatalf("CLI identities were not fresh: %+v", r)
			}
			ids[r.ExecutorID] = true
			runs[r.RunID] = true
			nonces[nonce] = true
		}
	})
	t.Run("installed_cli_timeout_after_startup", func(t *testing.T) { h.cliCase(t, "timeout") })
	t.Run("installed_cli_sigint_after_startup", func(t *testing.T) { h.cliCase(t, "sigint") })
}

type installedHarness struct {
	assets             Assets
	entry, evidenceDir string
	sibling            *Child
	mu                 sync.Mutex
	intervals          map[string]liveInterval
	concurrentReady    map[string]readyChild
	concurrentOverlap  bool
	startups           []time.Duration
}

// The whole-command timeout under test also bounds the installed demo's own
// bootstrap, so a fixed short value turns a slow start on a loaded host into a
// failure of the timeout behaviour. These bound the deadline the harness
// derives for that case instead.
const (
	minimumTimeoutDeadline = 8 * time.Second
	maximumTimeoutDeadline = 40 * time.Second
	timeoutStartupFactor   = 6
)

// timeoutDeadline sizes the whole-command timeout of the timeout case from the
// startups this harness already observed on this host, so the deadline under
// test expires after the demo has started rather than during its bootstrap.
func (h *installedHarness) timeoutDeadline() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	deadline := minimumTimeoutDeadline
	for _, startup := range h.startups {
		deadline = max(deadline, timeoutStartupFactor*startup)
	}
	return min(deadline, maximumTimeoutDeadline).Round(time.Second)
}

type liveInterval struct{ start, end time.Time }
type readyChild struct {
	child      *Child
	cli        processIdentity
	dispatcher processIdentity
}
type installedEvidence struct {
	Case                 string             `json:"case"`
	SourceSHA            string             `json:"source_sha"`
	Version              string             `json:"version"`
	Expected             string             `json:"expected"`
	Result               Result             `json:"result"`
	Error                string             `json:"error,omitempty"`
	ExitCode             int                `json:"exit_code"`
	DurationMS           int64              `json:"duration_ms"`
	FaultObserved        bool               `json:"fault_observed"`
	FaultAt              time.Time          `json:"fault_at,omitempty"`
	FaultResponseMS      int64              `json:"fault_response_ms,omitempty"`
	StartupObserved      bool               `json:"startup_observed"`
	StartupAt            time.Time          `json:"startup_at,omitempty"`
	FinishedAt           time.Time          `json:"finished_at"`
	CleanupBeforeHarness bool               `json:"cleanup_before_harness"`
	SiblingAlive         bool               `json:"sibling_alive"`
	Processes            []processIdentity  `json:"processes"`
	Listeners            []listenerIdentity `json:"listeners"`
	StateDirectories     []string           `json:"state_directories"`
	Observation          map[string]any     `json:"observation,omitempty"`
	Diagnostics          string             `json:"diagnostics,omitempty"`
}

func (h *installedHarness) save(t *testing.T, e installedEvidence) {
	t.Helper()
	e.SourceSHA = h.assets.Manifest.SourceSHA
	e.Version = h.assets.Manifest.Version
	e.SiblingAlive = !isDone(h.sibling.Done()) && syscall.Kill(h.sibling.PID(), 0) == nil
	if !e.SiblingAlive {
		t.Error("cleanup terminated the unrelated sibling")
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Error(err)
		return
	}
	// Test names are controlled literals, never paths supplied by the candidate.
	name := strings.ReplaceAll(t.Name(), "/", "-") + "-" + e.Case + ".json"
	if err := os.WriteFile(filepath.Join(h.evidenceDir, name), append(data, '\n'), 0600); err != nil {
		t.Error(err)
	}
	t.Logf("candidate=%s case=%s exit=%d cleanup_before_harness=%t evidence=%s", e.SourceSHA, e.Case, e.ExitCode, e.CleanupBeforeHarness, name)
}

func (h *installedHarness) libraryCase(t *testing.T, fault string) {
	t.Helper()
	// Canonical migration and real process startup share the normal total
	// execution bound. The separate fault-to-return assertion below includes
	// at most two seconds of response/stall and the five-second cleanup budget.
	limit := 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	track := newOwnership()
	var children []*Child
	var target targetProcess
	var mu sync.Mutex
	deps := productionDependencies()
	faultObserved := false
	var faultAt time.Time
	var observed map[string]any
	deps.bootstrap = func(ctx context.Context, role SchemaRole, path string) error {
		track.directory(filepath.Dir(path))
		return BootstrapFresh(ctx, role, path)
	}
	deps.startTarget = func(ctx context.Context, nonce string) (targetProcess, error) {
		var p targetProcess
		var err error
		if fault == "wrong_reply" || fault == "withheld_eof" {
			p, err = startAcceptanceTarget(ctx, nonce, fault)
		} else {
			p, err = startTarget(ctx, nonce)
		}
		if err == nil {
			mu.Lock()
			target = p
			mu.Unlock()
			track.captureListeners(os.Getpid(), p.Addr())
		}
		return p, err
	}
	deps.startChild = func(spec ChildSpec) (childProcess, error) {
		if fault == "executor_start_failure" && spec.Path == h.assets.Executor {
			mu.Lock()
			faultObserved = true
			faultAt = time.Now()
			mu.Unlock()
			return nil, errors.New("acceptance injected executor start failure")
		}
		child, err := StartChild(spec)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		children = append(children, child)
		mu.Unlock()
		track.process(child.PID())
		if fault == "dispatcher_early_death" && spec.Path == h.assets.Dispatcher {
			if _, err := awaitReady(ctx, spec.Args[3], child.PID(), ""); err != nil {
				return child, err
			}
			track.captureListeners(child.PID(), "")
			mu.Lock()
			faultAt = time.Now()
			mu.Unlock()
			if err := syscall.Kill(-child.PID(), syscall.SIGKILL); err != nil {
				return child, err
			}
			waitErr := child.Wait(ctx)
			var exit *exec.ExitError
			if !errors.As(waitErr, &exit) {
				return child, fmt.Errorf("join injected dispatcher death: %w", waitErr)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				return child, fmt.Errorf("dispatcher exited before injected SIGKILL: %w", waitErr)
			}
			mu.Lock()
			faultObserved = true
			mu.Unlock()
		}
		if fault == "diagnostic_overflow" && spec.Path == h.assets.Executor {
			// Inject at the documented private writer boundary after the real process
			// starts; this tests process cleanup after diagnostic overflow, not a
			// claim that the fixed demo guest generates excessive output.
			mu.Lock()
			faultObserved = true
			faultAt = time.Now()
			mu.Unlock()
			_, _ = spec.Stdout.Write(bytes.Repeat([]byte("x"), diagnosticLimit+1))
		}
		return child, nil
	}
	deps.observe = func(ctx context.Context, o observation) error {
		track.captureListeners(o.DispatcherPID, "")
		track.captureListeners(o.ExecutorPID, "")
		value, err := h.inspectObservation(ctx, o)
		mu.Lock()
		observed = value
		mu.Unlock()
		return err
	}
	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	started := time.Now()
	go func() { r, err := run(ctx, h.assets, deps); done <- outcome{r, err} }()
	var got outcome
	outerTimedOut := false
	select {
	case got = <-done:
	case <-time.After(limit + cleanupTimeout + time.Second):
		outerTimedOut = true
		got.err = errors.New("demo exceeded execution and cleanup budget")
		t.Error(got.err)
	}
	finishedAt := time.Now()
	mu.Lock()
	owned := append([]*Child(nil), children...)
	ownedTarget, didObserveFault, injectionAt, observationResult := target, faultObserved, faultAt, observed
	mu.Unlock()
	// Inspect BEFORE emergency teardown. The harness must never turn its own
	// cleanup into evidence that the candidate cleaned up correctly.
	cleanErr := track.verifyGone()
	for _, child := range owned {
		if !child.CleanupComplete() {
			cleanErr = errors.Join(cleanErr, fmt.Errorf("child %d reaper or cleanup controller remains", child.PID()))
		}
	}
	if ownedTarget != nil && !isDone(ownedTarget.Done()) {
		cleanErr = errors.Join(cleanErr, errors.New("target worker remains"))
	}
	e := installedEvidence{Case: fault, Expected: "failure", Result: got.result, DurationMS: finishedAt.Sub(started).Milliseconds(), FinishedAt: finishedAt, FaultObserved: didObserveFault, FaultAt: injectionAt, CleanupBeforeHarness: cleanErr == nil && !outerTimedOut, Observation: observationResult}
	if got.err != nil {
		e.Error = got.err.Error()
		e.ExitCode = 1
	}
	e.Processes, e.Listeners, e.StateDirectories = track.snapshot()
	if p, ok := ownedTarget.(*acceptanceTarget); ok {
		e.FaultObserved, e.FaultAt = p.faultState()
	}
	if fault != "success" {
		e.FaultResponseMS = finishedAt.Sub(e.FaultAt).Milliseconds()
		if e.FaultAt.IsZero() || finishedAt.Sub(e.FaultAt) > 2*time.Second+cleanupTimeout {
			t.Errorf("fault %s exceeded its response and cleanup budget or was never injected: injection=%s return=%s", fault, e.FaultAt, finishedAt)
		}
	}
	if fault == "success" {
		if len(e.Processes) != 2 || len(e.Listeners) < 3 || len(e.StateDirectories) != 1 {
			t.Errorf("incomplete library ownership evidence: processes=%d listeners=%d directories=%d", len(e.Processes), len(e.Listeners), len(e.StateDirectories))
		}
		e.Expected = "success"
		if got.err != nil || got.result.Cleanup != "complete" || observationResult == nil {
			t.Errorf("real installed traversal failed: %v", got.err)
		}
	} else if got.err == nil || got.result.Cleanup == "complete" || !e.FaultObserved {
		t.Errorf("fault %s was not exercised and rejected: observed=%t result=%+v err=%v", fault, e.FaultObserved, got.result, got.err)
	}
	if cleanErr != nil {
		t.Error("candidate cleanup:", cleanErr)
	}
	h.save(t, e)
	// Failure safety only. The recorded verdict above remains a failure.
	cancel()
	if ownedTarget != nil {
		c, end := context.WithTimeout(context.Background(), time.Second)
		_ = ownedTarget.Stop(c)
		end()
	}
	for _, child := range owned {
		if !child.CleanupComplete() {
			c, end := context.WithTimeout(context.Background(), time.Second)
			_ = child.Stop(c)
			end()
		}
	}
	if outerTimedOut {
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("supervisor callback did not join after emergency cleanup")
		}
	}
}

func (h *installedHarness) inspectObservation(ctx context.Context, o observation) (map[string]any, error) {
	u := url.URL{Scheme: "file", Path: o.DispatcherDB}
	db, err := sql.Open("sqlite", u.String()+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	q := database.New(db)
	tx, err := q.GetTransactionByID(ctx, o.Submission.TransactionID)
	if err != nil {
		return nil, err
	}
	if tx.Method != "TEST" || tx.Status != int64(models.Paid) || tx.Price != 960_000 || tx.Currency != "TEST" {
		return nil, fmt.Errorf("unexpected TEST transaction: method=%s status=%d price=%d currency=%q", tx.Method, tx.Status, tx.Price, tx.Currency)
	}
	orders, err := q.GetTransactionOrders(ctx, tx.ID)
	if err != nil {
		return nil, err
	}
	if len(orders) != 1 || orders[0].OrderID != 1 || orders[0].Price != 960_000 || orders[0].Currency != "TEST" || orders[0].ExecutorID != o.ExecutorID {
		return nil, fmt.Errorf("unexpected order rows: %+v", orders)
	}
	id, err := uuid.Parse(o.Result.RunID)
	if err != nil {
		return nil, err
	}
	row, err := q.GetDebugletByUUID(ctx, id)
	if err != nil {
		return nil, err
	}
	if row.State.String() != client.StateExited || row.Error.String != "" || row.ExecutorID != o.ExecutorID || row.TransactionID != tx.ID || row.OrderID != 1 {
		return nil, fmt.Errorf("unexpected terminal row for %s: state=%s error=%q", id, row.State.String(), row.Error.String)
	}
	c, err := client.New(o.Endpoint, client.Options{})
	if err != nil {
		return nil, err
	}
	version, err := c.Version(ctx)
	if err != nil {
		return nil, err
	}
	if version.Version != h.assets.Manifest.Version {
		return nil, fmt.Errorf("dispatcher version %q differs from candidate", version.Version)
	}
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) != 1 || nodes[0].ID != o.ExecutorID || !nodes[0].Ready || nodes[0].Version != h.assets.Manifest.Version {
		return nil, fmt.Errorf("executor identity differs: %+v", nodes)
	}
	state, err := c.Status(ctx, o.Result.RunID)
	if err != nil {
		return nil, err
	}
	if state.State != client.StateExited || state.Error != "" || state.ExecutorID != o.ExecutorID {
		return nil, fmt.Errorf("HTTP terminal result differs: %+v", state)
	}
	var output []byte
	var cursor int64
	for {
		page, err := c.Logs(ctx, o.Result.RunID, client.LogOptions{After: cursor, Limit: 100})
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Logs {
			if len(entry.Output) > guestOutputLimit-len(output) {
				return nil, errors.New("observed output exceeds limit")
			}
			output = append(output, entry.Output...)
		}
		cursor = page.After
		if !page.HasMore {
			break
		}
	}
	marker := "DEBUGLET_DEMO_OK " + o.Nonce + "\n"
	if !bytes.Contains(output, []byte(marker)) {
		return nil, errors.New("nonce marker absent from real HTTP logs")
	}
	cli, err := h.cliVersion(ctx, o.Dir, o.Endpoint)
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction_id": tx.ID, "transaction_method": tx.Method, "transaction_status": tx.Status, "transaction_price": tx.Price, "transaction_currency": tx.Currency, "order": orders[0], "run_id": o.Result.RunID, "executor_id": o.ExecutorID, "nonce": o.Nonce, "terminal_state": state.State, "output": string(output), "dispatcher_version": version.Version, "executor_version": nodes[0].Version, "cli_version": cli}, nil
}

func (h *installedHarness) cliVersion(parent context.Context, dir, endpoint string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.entry, "--endpoint", endpoint, "--output", "json", "version", "--server")
	cmd.Dir = dir
	cmd.Env = acceptanceEnvironment(dir)
	cmd.WaitDelay = time.Second
	var out, stderr acceptanceBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("installed version: %w: %s", err, stderr.String())
	}
	var v struct {
		Module, Version, Revision string
		Modified                  bool
		Server                    *client.ServerVersion
	}
	if err := decodeOne(out.Bytes(), &v); err != nil {
		return nil, err
	}
	if out.Overflow() || stderr.Overflow() || v.Module != "github.com/netsec-ethz/debuglet" || v.Version != h.assets.Manifest.Version || v.Revision != h.assets.Manifest.SourceSHA || v.Modified || v.Server == nil || v.Server.Version != v.Version {
		return nil, errors.New("installed CLI/server identity mismatch")
	}
	return map[string]any{"version": v.Version, "revision": v.Revision, "module": v.Module, "modified": v.Modified}, nil
}
func decodeOne(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}
func acceptanceEnvironment(tmp string) []string {
	return []string{"PATH=", "TMPDIR=" + tmp, "LANG=C", "LC_ALL=C", "TZ=UTC"}
}

type acceptanceBuffer struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *acceptanceBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	left := 3*diagnosticLimit - len(b.data)
	if len(p) > left {
		b.overflow = true
		p = p[:left]
	}
	b.data = append(b.data, p...)
	return n, nil
}
func (b *acceptanceBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data)
}
func (b *acceptanceBuffer) String() string { return string(b.Bytes()) }
func (b *acceptanceBuffer) Overflow() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.overflow }
