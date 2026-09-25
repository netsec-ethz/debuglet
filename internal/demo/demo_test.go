//go:build linux

package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/pelletier/go-toml/v2"
)

type scriptedChild struct {
	pid          int
	done         chan struct{}
	once         sync.Once
	stopErr      error
	onStop       func()
	stopDeadline time.Time
	groupPending bool
	joinOnRetry  bool
	stopCalls    int
}

func (c *scriptedChild) PID() int              { return c.pid }
func (c *scriptedChild) Done() <-chan struct{} { return c.done }
func (c *scriptedChild) CleanupComplete() bool { return isDone(c.done) && !c.groupPending }
func (c *scriptedChild) Wait(ctx context.Context) error {
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *scriptedChild) Stop(ctx context.Context) error {
	c.stopCalls++
	if c.stopCalls > 1 && c.joinOnRetry {
		c.groupPending = false
		return ErrForcedKill
	}
	c.once.Do(func() {
		c.stopDeadline, _ = ctx.Deadline()
		if c.onStop != nil {
			c.onStop()
		}
		close(c.done)
	})
	return c.stopErr
}

type scriptedTarget struct {
	addr         string
	done         chan struct{}
	once         sync.Once
	err          error
	onStop       func()
	stopDeadline time.Time
}

func (s *scriptedTarget) Addr() string          { return s.addr }
func (s *scriptedTarget) Done() <-chan struct{} { return s.done }
func (s *scriptedTarget) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *scriptedTarget) Stop(ctx context.Context) error {
	s.stopDeadline, _ = ctx.Deadline()
	if s.onStop != nil {
		s.onStop()
	}
	s.once.Do(func() { close(s.done) })
	return nil
}

func TestDemoCleanupBudget(t *testing.T) {
	f := newSupervisorFixture(t, "success")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := run(ctx, f.assets, f.deps); err != nil {
		t.Fatal(err)
	}
	// The recorded deadlines are inputs received by independent owners.
	// Earlier owners must leave budget for those not yet stopped, and all
	// deadlines must remain inside the original five-second cleanup window.
	dispatcherEnd := f.children[0].stopDeadline
	executorEnd := f.children[1].stopDeadline
	if !f.target.stopDeadline.Before(executorEnd) || !executorEnd.Before(dispatcherEnd) {
		t.Fatalf("cleanup did not reserve later owners' budget: target=%v executor=%v dispatcher=%v", f.target.stopDeadline, executorEnd, dispatcherEnd)
	}
	if dispatcherEnd.After(time.Now().Add(cleanupTimeout)) || !dispatcherEnd.After(start) {
		t.Fatal("cleanup deadline exceeds the shared budget")
	}
}

func TestDemoCleanupRequiresGroupCompletion(t *testing.T) {
	for _, mode := range []string{"group still present", "group completes on rejoin", "forced cleanup"} {
		t.Run(mode, func(t *testing.T) {
			f := newSupervisorFixture(t, mode)
			// The scripted fixture owns no OS child group. Release only its
			// retained test directory once we have inspected Run's decision.
			t.Cleanup(func() {
				if f.dir != "" {
					if err := os.RemoveAll(f.dir); err != nil {
						t.Error(err)
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result, err := run(ctx, f.assets, f.deps)
			if err == nil || result.Cleanup == "complete" || !f.observed {
				t.Fatalf("cleanup failure reported success: %+v, observed=%t, err=%v", result, f.observed, err)
			}
			executor := f.children[1]
			if !isDone(executor.Done()) {
				t.Fatal("fixture must have reaped its direct child")
			}
			_, statErr := os.Stat(f.dir)
			if mode == "group still present" {
				if executor.stopCalls != 2 || executor.CleanupComplete() || statErr != nil || !strings.Contains(err.Error(), "retained owned state at "+f.dir) {
					t.Fatalf("incomplete group lost state or rejoin: calls=%d complete=%t stat=%v err=%v", executor.stopCalls, executor.CleanupComplete(), statErr, err)
				}
			} else if !executor.CleanupComplete() || !errors.Is(statErr, os.ErrNotExist) || !errors.Is(err, ErrForcedKill) {
				t.Fatalf("joined forced cleanup must remove state but fail: complete=%t stat=%v err=%v", executor.CleanupComplete(), statErr, err)
			}
			if mode == "group completes on rejoin" && executor.stopCalls != 2 {
				t.Fatalf("existing teardown not rejoined: %d calls", executor.stopCalls)
			}
		})
	}
}
func (s *scriptedTarget) finish() { s.once.Do(func() { close(s.done) }) }

type supervisorFixture struct {
	t                              *testing.T
	mu                             sync.Mutex
	assets                         Assets
	deps                           dependencies
	server                         *httptest.Server
	nonce, executorID, dir         string
	intents, submissions, logReads int
	stops                          []string
	children                       []*scriptedChild
	target                         *scriptedTarget
	mode                           string
	observed                       bool
}

func newSupervisorFixture(t *testing.T, mode string) *supervisorFixture {
	t.Helper()
	root := t.TempDir()
	guest := filepath.Join(root, "demo.wasm")
	if err := os.WriteFile(guest, []byte("fixture guest; no WASM execution claimed"), 0644); err != nil {
		t.Fatal(err)
	}
	f := &supervisorFixture{t: t, mode: mode, assets: Assets{Root: root, CLI: filepath.Join(root, "dbl"), Dispatcher: filepath.Join(root, "dispatcher"), Executor: filepath.Join(root, "executor"), Guest: guest, Manifest: Manifest{Version: "test-version"}}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.deps = dependencies{
		resolveAssets: func(string) (Assets, error) {
			if mode == "missing assets" {
				return Assets{}, errors.New("missing assets")
			}
			return f.assets, nil
		},
		bootstrap: func(ctx context.Context, role SchemaRole, path string) error {
			f.dir = filepath.Dir(path)
			if mode == "bootstrap failure" {
				return errors.New("bootstrap sentinel")
			}
			return os.WriteFile(path, nil, 0600)
		},
		checkSchema: func(ctx context.Context, role SchemaRole, path string) error {
			if mode == "unsupported schema" {
				return fmt.Errorf("%s schema sentinel", role)
			}
			if _, err := os.Lstat(path); err != nil {
				return err
			}
			return nil
		},
		startChild: f.startChild,
		startTarget: func(ctx context.Context, nonce string) (targetProcess, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.nonce = nonce
			s := &scriptedTarget{addr: f.server.Listener.Addr().String(), done: make(chan struct{}), onStop: func() { f.stops = append(f.stops, "target") }}
			if mode == "wrong target reply" {
				s.err = errors.New("incorrect acknowledgement")
			}
			if mode != "withheld acknowledgement" {
				s.finish()
			}
			f.target = s
			return s, nil
		},
		observe: func(ctx context.Context, o observation) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.observed = true
			if o.Dir != f.dir || o.Nonce != f.nonce || o.ExecutorID != f.executorID || o.Submission.TransactionID != "transaction" || o.Result.State != client.StateExited {
				return fmt.Errorf("incorrect observation: %+v", o)
			}
			for _, path := range []string{o.DispatcherDB, o.ExecutorDB} {
				if _, err := os.Stat(path); err != nil {
					return err
				}
			}
			if len(f.stops) != 0 {
				return errors.New("observer ran after cleanup")
			}
			return nil
		},
	}
	return f
}

func (f *supervisorFixture) startChild(spec ChildSpec) (childProcess, error) {
	name := "dispatcher"
	if spec.Path == f.assets.Executor {
		name = "executor"
	}
	if f.mode == "executor startup failure" && name == "executor" {
		return nil, errors.New("executor start sentinel")
	}
	data, err := os.ReadFile(spec.Args[1])
	if err != nil {
		return nil, err
	}
	var config map[string]map[string]any
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	if spec.Dir != f.dir || len(spec.Env) != 4 || spec.Stdout != spec.Stderr {
		return nil, errors.New("child isolation or shared diagnostic bound drift")
	}
	if info, err := os.Stat(spec.Dir); err != nil || info.Mode().Perm() != 0700 {
		return nil, errors.New("state directory is not private")
	}
	for _, kv := range spec.Env {
		if strings.HasPrefix(kv, "SCION_") || strings.HasPrefix(kv, "SUI_") || strings.HasPrefix(kv, "HOME=") {
			return nil, errors.New("inherited machine configuration")
		}
	}
	c := &scriptedChild{pid: 100 + len(f.children), done: make(chan struct{}), onStop: func() { f.stops = append(f.stops, name) }}
	if f.mode == "forced cleanup" && name == "executor" {
		c.stopErr = ErrForcedKill
	}
	if (f.mode == "group still present" || f.mode == "group completes on rejoin") && name == "executor" {
		c.stopErr = context.DeadlineExceeded
		c.groupPending = true
		c.joinOnRetry = f.mode == "group completes on rejoin"
	}
	f.children = append(f.children, c)
	record := readiness.Record{SchemaVersion: 1, PID: c.pid}
	if name == "dispatcher" {
		if config["sui"]["disabled"] != true || config["server"]["bind_host"] != "127.0.0.1" {
			return nil, errors.New("dispatcher config is not wallet-free loopback")
		}
		record.HTTPAddr = strings.TrimPrefix(f.server.URL, "http://")
		record.GRPCAddr = record.HTTPAddr // A scripted child; no gRPC listener claim.
	} else {
		if config["network"]["packet_counter"] != "fallback" || config["network"]["disable_scion_environment"] != true || config["network"]["interface"] != "" {
			return nil, errors.New("fallback/SCION isolation drift")
		}
		f.mu.Lock()
		f.executorID = config["identity"]["executor_id"].(string)
		record.ExecutorID = f.executorID
		f.mu.Unlock()
	}
	if f.mode == "early death" && name == "dispatcher" {
		c.once.Do(func() { close(c.done) })
		return c, nil
	}
	if f.mode == "diagnostic overflow" && name == "executor" {
		spec.Stdout.Write(bytes.Repeat([]byte("x"), diagnosticLimit))
		spec.Stderr.Write([]byte("overflow"))
	}
	if f.mode == "wrong ready PID" && name == "executor" {
		record.PID++
	}
	if f.mode == "missing readiness" && name == "executor" {
		return c, nil
	}
	encoded, _ := json.Marshal(record)
	if err := os.WriteFile(spec.Args[3], encoded, 0600); err != nil {
		return nil, err
	}
	return c, nil
}

func (f *supervisorFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	const id = "11111111-1111-4111-8111-111111111111"
	write := func(v any) { json.NewEncoder(w).Encode(v) }
	switch r.Method + " " + r.URL.Path {
	case "GET /executors":
		if f.executorID == "" {
			write([]client.Node{})
			return
		}
		write([]client.Node{{ID: f.executorID, Ready: f.mode != "not resource ready"}})
	case "PUT /payment/intent":
		f.intents++
		write(map[string]any{"method": "TEST", "intent": map[string]string{"transaction_id": "transaction", "auth_key": ""}})
	case "PUT /debuglet":
		f.submissions++
		var req struct {
			Debuglets []client.Request `json:"debuglets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Debuglets) != 1 {
			http.Error(w, "invalid fixture request", 400)
			return
		}
		job := req.Debuglets[0]
		if job.OrderID != 1 || job.ExecutorID != f.executorID || len(job.Args) != 2 || job.Args[1] != f.nonce || job.Policy.FloorBW != 64_000 || job.Policy.CeilBW != 1_000_000 || job.Policy.TimeoutMS != 15_000 {
			http.Error(w, "demo request contract drift", 400)
			return
		}
		if f.mode == "submission failure" {
			http.Error(w, "submission sentinel", 500)
			return
		}
		write([]string{id})
	case "GET /debuglet/" + id + "/state":
		message := ""
		if f.mode == "workload failure" {
			message = "guest sentinel"
		}
		write(client.State{State: client.StateExited, ExecutorID: f.executorID, Error: message})
	case "GET /debuglet/" + id + "/logs":
		f.logReads++
		// First terminal page deliberately has no marker; later HTTP output
		// is fragmented across pages. Terminal state must not stop polling.
		after := r.URL.Query().Get("after")
		if f.logReads == 1 {
			write(client.LogPage{State: client.StateExited, After: 0})
			return
		}
		marker := "DEBUGLET_DEMO_OK " + f.nonce + "\n"
		if f.mode == "output overflow" {
			marker = strings.Repeat("x", guestOutputLimit+1)
		}
		if f.mode == "missing marker" {
			marker = "unrelated output\n"
		}
		switch after {
		case "0":
			write(client.LogPage{State: client.StateExited, After: 1, Logs: []client.LogEntry{{ID: 1, Output: []byte(marker[:10])}}, HasMore: true})
		case "1":
			write(client.LogPage{State: client.StateExited, After: 2, Logs: []client.LogEntry{{ID: 2, Output: []byte(marker[10:])}}})
		default:
			write(client.LogPage{State: client.StateExited, After: 2})
		}
	default:
		http.NotFound(w, r)
	}
}

func TestDemoSupervisor(t *testing.T) {
	for _, mode := range []string{"success", "missing assets", "bootstrap failure", "executor startup failure", "early death", "wrong ready PID", "missing readiness", "not resource ready", "wrong target reply", "withheld acknowledgement", "missing marker", "output overflow", "diagnostic overflow", "submission failure", "workload failure", "forced cleanup"} {
		t.Run(mode, func(t *testing.T) {
			f := newSupervisorFixture(t, mode)
			bound := 2 * time.Second
			if mode == "missing readiness" || mode == "not resource ready" || mode == "withheld acknowledgement" || mode == "missing marker" {
				bound = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), bound)
			defer cancel()
			result, err := run(ctx, f.assets, f.deps)
			f.mu.Lock()
			defer f.mu.Unlock()
			if mode == "success" {
				if err != nil || result.Cleanup != "complete" || !f.observed {
					t.Fatalf("result %+v, observed=%t: %v", result, f.observed, err)
				}
				if f.intents != 1 || f.submissions != 1 || f.logReads < 3 {
					t.Fatalf("request counts intent=%d submit=%d logs=%d", f.intents, f.submissions, f.logReads)
				}
			} else if err == nil || result.Cleanup == "complete" {
				t.Fatalf("failed mode succeeded: %+v", result)
			}
			if mode == "forced cleanup" && !errors.Is(err, ErrForcedKill) {
				t.Fatalf("forced cleanup lost classification: %v", err)
			}
			if mode == "missing marker" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline lost: %v", err)
			}
			if f.submissions > 1 || f.intents > 1 {
				t.Fatal("mutation retried")
			}
			if f.dir != "" {
				if _, err := os.Stat(f.dir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("state not removed: %v", err)
				}
			}
			for _, child := range f.children {
				if !isDone(child.Done()) {
					t.Fatal("child not joined")
				}
			}
			if f.target != nil && len(f.stops) > 0 && f.stops[0] != "target" {
				t.Fatalf("cleanup order: %v", f.stops)
			}
			if len(f.stops) == 3 && strings.Join(f.stops, ",") != "target,executor,dispatcher" {
				t.Fatalf("cleanup order: %v", f.stops)
			}
		})
	}
}

func TestDemoReadinessValidation(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":1,"pid":8,"http_addr":"127.0.0.1:20","grpc_addr":"127.0.0.1:21"}`,
		`{"schema_version":2,"pid":7,"http_addr":"127.0.0.1:20","grpc_addr":"127.0.0.1:21"}`,
		`{"schema_version":1,"pid":7,"http_addr":"example.com:20","grpc_addr":"127.0.0.1:21"}`,
		`{"schema_version":1,"pid":7,"http_addr":"127.0.0.1:0","grpc_addr":"127.0.0.1:21"}`,
		`{"schema_version":1,"pid":7,"http_addr":"127.0.0.1:20","grpc_addr":"127.0.0.1:21"} {}`,
		strings.Repeat("x", readyLimit+1),
	} {
		path := filepath.Join(t.TempDir(), "ready.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := awaitReady(ctx, path, 7, "")
		cancel()
		if err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
}

func TestDemoDiagnosticLimit(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	log, err := newBoundedLog(filepath.Join(t.TempDir(), "child.log"), cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if n, err := log.Write(bytes.Repeat([]byte("x"), diagnosticLimit)); err != nil || n != diagnosticLimit {
		t.Fatal(n, err)
	}
	if ctx.Err() != nil {
		t.Fatal("exact limit rejected")
	}
	if n, err := io.WriteString(log, "extra"); n != 5 || err != nil {
		t.Fatal("overflow must keep draining", n, err)
	}
	if ctx.Err() == nil || len(log.Bytes()) != diagnosticLimit {
		t.Fatal("overflow not bounded/reported")
	}
}
