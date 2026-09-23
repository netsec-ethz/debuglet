package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	apispec "github.com/netsec-ethz/debuglet/api"
	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testExecutor = "84b8f75e-a779-465a-8ce3-54b04ac15ef2"
const testRun = "e733751c-073b-4b14-81ca-9b8eae3583cc"
const testTransaction = "0123456789abcdef0123456789abcdef"
const testNonce = "abcdef0123456789abcdef0123456789"

// payloadFiles is the metadata of every installed payload but the manifest
// itself, which is what a resolved installation reports.
func payloadFiles(digest string) map[string]artifact.File {
	files := map[string]artifact.File{}
	for name := range artifact.PayloadModes() {
		if name != artifact.ManifestPath {
			files[name] = artifact.File{Bytes: 1, SHA256: strings.Repeat(digest, 64)}
		}
	}
	return files
}

func manifestFixture() Manifest {
	return Manifest{SchemaVersion: 1, Environment: "local", Operator: "Local fixture_1.test-run", ExecutorID: testExecutor,
		Control: ControlManifest{Protection: "owned-loopback"}, Target: TargetManifest{Host: "127.0.0.1"},
		Limits: LimitsManifest{ExecutionMS: 10_000, CeilingBPS: 1_000_000, AttemptMS: 180_000}, SourceSHA256: strings.Repeat("a", 64)}
}

func driverOptions(t *testing.T) Options {
	t.Helper()
	m := manifestFixture()
	m.Operator, m.SourceSHA256 = "test owner", strings.Repeat("b", 64)
	m.Limits = LimitsManifest{ExecutionMS: 1000, CeilingBPS: 1_000_000, AttemptMS: 30000}
	return Options{Manifest: m, Assets: demo.Assets{Root: "/installed", CLI: "/installed/bin/dbl", Dispatcher: "/installed/bin/debuglet-dispatcher", Executor: "/installed/bin/debuglet-executor", Guest: "/installed/share/debuglet/demo.wasm", Manifest: demo.Manifest{SchemaVersion: 1, Version: "v0.0.1-test", SourceSHA: strings.Repeat("c", 40), GoVersion: artifact.Toolchain, GOOS: "linux", GOARCH: "amd64", GuestABI: artifact.GuestABI, Files: payloadFiles("a")}}, ArchiveSHA256: strings.Repeat("d", 64), EvidenceDir: filepath.Join(t.TempDir(), "result")}
}

type scriptedSession struct {
	t                                      *testing.T
	opts                                   Options
	fault                                  string
	started, stopped                       bool
	submissions, logCalls, polls, cleanups int
	calls                                  [][]string
	stateDir                               string
}

func (s *scriptedSession) StartDispatcher(context.Context) (string, error) {
	if s.fault == "proxy_start" {
		return "", errors.New("fixture proxy")
	}
	return "http://127.0.0.1:12345/api", nil
}
func (s *scriptedSession) StartExecutor(context.Context) error {
	if s.fault == "broken_control" {
		return errors.New("fixture control")
	}
	s.started = true
	return nil
}
func (s *scriptedSession) StartTarget(context.Context) (string, string, error) {
	return "127.0.0.1:12346", testNonce, nil
}
func (s *scriptedSession) TargetACK(context.Context) error {
	if s.fault == "ack" {
		return errors.New("no target ACK")
	}
	return nil
}
func (s *scriptedSession) CloseTarget(context.Context) error { return nil }
func (s *scriptedSession) StopExecutor(context.Context) error {
	s.stopped = true
	if s.fault == "stop" {
		return demo.ErrForcedKill
	}
	return nil
}
func (s *scriptedSession) Cleanup(context.Context) (CleanupEvidence, error) {
	s.cleanups++
	if s.fault == "cleanup" {
		return CleanupEvidence{ChildrenReaped: ptr(false), ForcedKills: ptr(0)}, errors.New("incomplete group")
	}
	if s.fault == "forced_joined" || s.fault == "stop" {
		return CleanupEvidence{ChildrenReaped: ptr(true), ForcedKills: ptr(1)}, demo.ErrForcedKill
	}
	return CleanupEvidence{ChildrenReaped: ptr(true), ForcedKills: ptr(0)}, nil
}

// scriptedServerVersion mirrors the identities an installed candidate reports
// through dbl version --server.
func scriptedServerVersion(version, revision string) client.ServerVersion {
	return client.ServerVersion{
		Version:         version,
		APIVersion:      apispec.Version,
		APIVersions:     []string{"1"},
		BinaryVersion:   version,
		BinaryRevision:  revision,
		ProtocolVersion: "3",
	}
}

func doc(v any) commandResult {
	b, _ := json.Marshal(v)
	return commandResult{Started: true, Stdout: b}
}
func (s *scriptedSession) Execute(ctx context.Context, args []string) commandResult {
	s.t.Helper()
	s.calls = append(s.calls, append([]string(nil), args...))
	if len(args) < 7 || args[0] != "--endpoint" || args[1] != "http://127.0.0.1:12345/api" || args[2] != "--timeout" || args[4] != "--output" || args[5] != "json" {
		s.t.Fatalf("invalid global CLI prefix: %q", args)
	}
	remaining, err := time.ParseDuration(args[3])
	if err != nil || remaining <= 0 || remaining > 30*time.Second {
		s.t.Fatalf("invalid remaining timeout: %q", args[3])
	}
	switch args[6] {
	case "version":
		if s.fault == "proxy_error" {
			return commandResult{Started: true, Err: errors.New("proxy response")}
		}
		server := scriptedServerVersion(s.opts.Assets.Manifest.Version, s.opts.Assets.Manifest.SourceSHA)
		if s.fault == "version_fields" {
			// A dispatcher that reports only its configured version: the
			// candidate no longer says which contract it serves.
			server = client.ServerVersion{Version: s.opts.Assets.Manifest.Version}
		}
		return doc(map[string]any{"module": "github.com/netsec-ethz/debuglet", "version": s.opts.Assets.Manifest.Version, "revision": s.opts.Assets.Manifest.SourceSHA, "modified": false, "server": server})
	case "nodes":
		if s.started && s.fault == "ready_override" {
			r := doc([]client.Node{{ID: testExecutor, Ready: false, Version: s.opts.Assets.Manifest.Version, TeslaDelaySec: 2, Currency: "TEST"}})
			r.Stdout = bytes.Replace(r.Stdout, []byte(`"ready":false`), []byte(`"ready":false,"Ready":true`), 1)
			return r
		}
		if s.started && s.fault == "ready_missing" {
			r := doc([]client.Node{{ID: testExecutor, Ready: true, Version: s.opts.Assets.Manifest.Version, TeslaDelaySec: 2, Currency: "TEST"}})
			r.Stdout = bytes.Replace(r.Stdout, []byte(`"ready":true,`), nil, 1)
			return r
		}
		if !s.started && s.fault != "duplicate" || s.stopped && s.fault != "registry_stays" {
			return doc([]client.Node{})
		}
		id := testExecutor
		if s.fault == "wrong_node" {
			id = testRun
		}
		return doc([]client.Node{{ID: id, Ready: true, Version: s.opts.Assets.Manifest.Version, TeslaDelaySec: 2, Currency: "TEST"}})
	case "run":
		s.submissions++
		want := []string{"run", "--wasm", s.opts.Assets.Guest, "--executor", testExecutor, "--allow", "127.0.0.1", "--duration", "1s", "--floor-bps", "64000", "--ceil-bps", "1000000", "--wait", "--", "127.0.0.1:12346", testNonce}
		if !reflect.DeepEqual(args[6:], want) {
			s.t.Fatalf("run args=%q", args[6:])
		}
		r := RunReceipt{ID: testRun, TransactionID: testTransaction, ExecutorID: testExecutor, State: client.StateExited}
		switch s.fault {
		case "not_started":
			return commandResult{Err: errors.New("exec failed")}
		case "timeout_unobserved":
			return commandResult{Started: true, Err: context.DeadlineExceeded}
		case "empty_receipt":
			return commandResult{Started: true, Err: errors.New("CLI exit 1")}
		case "wrong_receipt_executor":
			r.ExecutorID = testRun
		case "wrong_receipt_run":
			r.ID = "not-a-uuid"
		case "wrong_transaction":
			r.TransactionID = testRun
		case "unknown_state":
			r.State = "RunStateFuture"
		case "terminal_failed":
			r.Error = "private diagnostic content"
		case "submission_unknown":
			r.ID = ""
			r.State = "submission_unknown"
		case "submission_failed":
			r.ID = ""
			r.State = "submission_failed"
		case "running_receipt":
			r.State = "RunStateStarted"
		}
		result := doc(r)
		if s.fault == "cli_error_known" || s.fault == "submission_unknown" || s.fault == "submission_failed" || s.fault == "running_receipt" {
			result.Err = errors.New("CLI failed private diagnostic")
		}
		return result
	case "status":
		if s.fault == "error_override" {
			return commandResult{Started: true, Stdout: []byte(`{"id":"` + testRun + `","state":"RunStateExited","error":"failure","Error":"","executor_id":"` + testExecutor + `"}`)}
		}
		if s.fault == "status_error" {
			return doc(map[string]any{"id": testRun, "state": client.StateExited, "error": "private status diagnostic", "executor_id": testExecutor})
		}
		id := testRun
		if s.fault == "wrong_status_id" {
			id = testExecutor
		}
		return doc(map[string]any{"id": id, "state": client.StateExited, "error": "", "executor_id": testExecutor})
	case "logs":
		s.logCalls++
		if s.fault == "logs_error" {
			return doc(client.LogPage{State: client.StateExited, Error: "private logs diagnostic"})
		}
		if s.fault == "missing_nonce" || s.fault == "delayed_output" && s.logCalls == 1 {
			return doc(client.LogPage{State: client.StateExited})
		}
		if s.fault == "nonadvancing" {
			return doc(client.LogPage{State: client.StateExited, After: 0, Logs: []client.LogEntry{{ID: 0, Output: []byte("DEBUGLET_DEMO_OK " + testNonce + "\n")}}})
		}
		if s.logCalls == 1 || s.fault == "delayed_output" && s.logCalls == 2 {
			return doc(client.LogPage{State: client.StateExited, After: 1, Logs: []client.LogEntry{{ID: 1, Output: []byte("DEBUGLET_DEMO_")}}, HasMore: true})
		}
		return doc(client.LogPage{State: client.StateExited, After: 2, Logs: []client.LogEntry{{ID: 2, Output: []byte("OK " + testNonce + "\n")}}})
	default:
		s.t.Fatalf("unexpected command %q", args[6])
		return commandResult{}
	}
}
func scriptedDependencies(t *testing.T, opts Options, s *scriptedSession) driverDependencies {
	return driverDependencies{validate: Validate, resolve: func(string) (demo.Assets, error) { return opts.Assets, nil }, open: func(_ Options, dir string) localSession { s.stateDir = dir; return s }, write: WriteEvidence, poll: func(context.Context) error {
		s.polls++
		if s.fault == "missing_nonce" || s.fault == "registry_stays" {
			return context.DeadlineExceeded
		}
		return nil
	}}
}
func TestDryRunNoEffects(t *testing.T) {
	for _, mutation := range []string{"none", "manifest", "digest", "assets"} {
		t.Run(mutation, func(t *testing.T) {
			opts := driverOptions(t)
			opts.DryRun = true
			switch mutation {
			case "manifest":
				opts.Manifest.Environment = "eth-dev"
			case "digest":
				opts.ArchiveSHA256 = "bad"
			}
			opens, writes, resolves := 0, 0, 0
			deps := productionDependencies()
			deps.resolve = func(string) (demo.Assets, error) {
				resolves++
				a := opts.Assets
				if mutation == "assets" {
					a.Executor = "/substituted"
				}
				return a, nil
			}
			deps.open = func(Options, string) localSession {
				opens++
				t.Fatal("dry run created process/listener session")
				return nil
			}
			deps.write = func(string, Evidence) error { writes++; return nil }
			ev, err := runDriver(context.Background(), opts, deps)
			if mutation == "none" {
				if err != nil || ev.Outcome != "plan" || resolves != 1 {
					t.Fatalf("plan=%+v err=%v resolves=%d", ev, err, resolves)
				}
			} else if !errors.Is(err, errInvalidInput) {
				t.Fatalf("invalid input accepted: %+v %v", ev, err)
			}
			if opens != 0 || writes != 0 {
				t.Fatal("dry run had side effects")
			}
			if _, err := os.Lstat(opts.EvidenceDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("evidence path created: %v", err)
			}
		})
	}
}
func TestCanaryDriverFailures(t *testing.T) {
	for _, fault := range []string{"success", "delayed_output", "ready_override", "ready_missing", "error_override", "status_error", "logs_error", "duplicate", "wrong_node", "broken_control", "proxy_start", "proxy_error", "not_started", "timeout_unobserved", "empty_receipt", "wrong_receipt_executor", "wrong_receipt_run", "wrong_transaction", "unknown_state", "terminal_failed", "submission_unknown", "submission_failed", "running_receipt", "cli_error_known", "ack", "wrong_status_id", "missing_nonce", "nonadvancing", "cleanup", "forced_joined", "stop", "registry_stays", "version_fields"} {
		t.Run(fault, func(t *testing.T) {
			opts := driverOptions(t)
			s := &scriptedSession{t: t, opts: opts, fault: fault}
			ev, err := runDriver(context.Background(), opts, scriptedDependencies(t, opts, s))
			success := fault == "success" || fault == "delayed_output"
			if (err == nil) != success || (ev.Outcome == "passed") != success {
				t.Fatalf("fault=%s evidence=%+v err=%v", fault, ev, err)
			}
			if s.cleanups != 1 || s.submissions > 1 {
				t.Fatalf("cleanup=%d submits=%d", s.cleanups, s.submissions)
			}
			if success && (ev.RunID == nil || *ev.RunID != testRun || ev.Target.ACK == nil || !*ev.Target.ACK || ev.OutputMarkerSeen == nil || !*ev.OutputMarkerSeen || ev.Cleanup.RegistryIneligible == nil || !*ev.Cleanup.RegistryIneligible || s.logCalls < 2) {
				t.Fatalf("missing successful observations: %+v", ev)
			}
			switch fault {
			case "ready_override", "ready_missing", "duplicate", "wrong_node", "broken_control", "proxy_start", "proxy_error", "not_started":
				if ev.Submission != nil {
					t.Fatalf("fabricated submission: %+v", ev.Submission)
				}
			case "timeout_unobserved", "empty_receipt", "wrong_receipt_executor", "wrong_receipt_run", "wrong_transaction", "unknown_state":
				if ev.RunID != nil || ev.Submission == nil || ev.Submission.State != "unobserved" || !ev.Submission.OutcomeUnknown || ev.Submission.TransactionID != nil {
					t.Fatalf("uncertainty lost: %+v", ev)
				}
			case "cli_error_known", "running_receipt":
				if ev.RunID == nil || *ev.RunID != testRun || ev.Submission == nil || ev.Submission.OutcomeUnknown {
					t.Fatalf("known receipt lost: %+v", ev)
				}
			case "submission_unknown", "submission_failed":
				if ev.RunID != nil || ev.Submission == nil || ev.Submission.State != fault || ev.Submission.OutcomeUnknown != (fault == "submission_unknown") || ev.Terminal.State != nil {
					t.Fatalf("uncertainty receipt: %+v", ev)
				}
			}
			if fault == "cleanup" {
				if ev.Cleanup.StateRemoved == nil || *ev.Cleanup.StateRemoved {
					t.Fatal("incomplete group allowed state removal")
				}
				if _, err := os.Stat(s.stateDir); err != nil {
					t.Fatal("incomplete state not retained")
				}
			} else {
				if _, err := os.Lstat(s.stateDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("owned state remains: %v", err)
				}
			}
			data, e := os.ReadFile(filepath.Join(opts.EvidenceDir, "result.json"))
			if e != nil {
				t.Fatal(e)
			}
			var stored Evidence
			if json.Unmarshal(data, &stored) != nil || !reflect.DeepEqual(stored, ev) {
				t.Fatal("persisted and returned evidence differ")
			}
			if fault == "terminal_failed" || fault == "status_error" || fault == "logs_error" {
				if ev.Terminal.Error == nil || *ev.Terminal.Error != "workload reported an error" {
					t.Fatalf("terminal error observation lost: %+v", ev.Terminal)
				}
			}
			if ev.Error != nil && strings.Contains(*ev.Error, "private") {
				t.Fatal("raw diagnostics leaked")
			}
		})
	}
}

func TestInvalidInputRedaction(t *testing.T) {
	opts := driverOptions(t)
	secret := "https://user:secret@host"
	opts.ArchiveSHA256 = secret
	deps := productionDependencies()
	deps.resolve = func(string) (demo.Assets, error) {
		t.Fatal("invalid input reached provenance")
		return demo.Assets{}, nil
	}
	deps.open = func(Options, string) localSession { t.Fatal("invalid input started runtime"); return nil }
	ev, err := runDriver(context.Background(), opts, deps)
	if !errors.Is(err, errInvalidInput) {
		t.Fatal(err)
	}
	data, _ := json.Marshal(ev)
	if bytes.Contains(data, []byte("secret")) || ev.ArchiveSHA256 != "" {
		t.Fatalf("unvalidated input reflected: %s", data)
	}
	// Exercise the actual command parser/output boundary using a verified inert
	// payload. These bytes are hashed/read only; invalid input must never execute.
	root := t.TempDir()
	opts.Assets.Root = root
	files := map[string]artifact.File{}
	for name, mode := range artifact.PayloadModes() {
		if name == artifact.ManifestPath {
			continue
		}
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("inert fixture"), mode); err != nil {
			t.Fatal(err)
		}
		info, err := artifact.HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = info
	}
	opts.Assets.Manifest.Files = files
	metadata, _ := json.Marshal(opts.Assets.Manifest)
	if err := os.WriteFile(filepath.Join(root, artifact.ManifestPath), metadata, 0644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	manifestJSON, _ := json.Marshal(opts.Manifest)
	if err := os.WriteFile(manifestPath, manifestJSON, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := mainCommand(context.Background(), []string{"-manifest", manifestPath, "-installed-root", root, "-archive-sha256", secret, "-evidence-dir", opts.EvidenceDir}, &stdout, &stderr)
	if code != 2 || strings.Contains(stdout.String()+stderr.String(), "secret") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(opts.EvidenceDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid input created evidence/state")
	}
}

func TestEvidencePersistenceFailureIsNotSuccess(t *testing.T) {
	opts := driverOptions(t)
	s := &scriptedSession{t: t, opts: opts, fault: "success"}
	deps := scriptedDependencies(t, opts, s)
	writes := 0
	deps.write = func(dir string, ev Evidence) error {
		writes++
		if err := WriteEvidence(dir, ev); err != nil {
			t.Fatal(err)
		}
		return errors.New("post-publication fixture failure")
	}
	ev, err := runDriver(context.Background(), opts, deps)
	if err == nil || ev.Outcome != "failed" || ev.Phase != "cleanup" || writes != 1 {
		t.Fatalf("persistence failure accepted: %+v %v writes=%d", ev, err, writes)
	}
}
