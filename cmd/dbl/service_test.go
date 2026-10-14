package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/demo/service"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

// recordingManager is the command's view of a service manager: enough to check
// that the command drives one unit and reports what it read back, without a
// live manager. Readiness itself is covered where it is implemented, in
// internal/demo/service.
type recordingManager struct {
	calls         []string
	enabled       map[string]bool
	unitDirectory string
	// mainPID, when nonzero, is the process every unit reports running.
	mainPID int
}

func newRecordingManager() *recordingManager {
	return &recordingManager{enabled: map[string]bool{}}
}

func (m *recordingManager) Reload(context.Context) error {
	m.calls = append(m.calls, "reload")
	return nil
}

func (m *recordingManager) Enable(_ context.Context, unit string) error {
	m.calls = append(m.calls, "enable "+unit)
	m.enabled[unit] = true
	return nil
}

func (m *recordingManager) Disable(_ context.Context, unit string) error {
	m.calls = append(m.calls, "disable "+unit)
	m.enabled[unit] = false
	return nil
}

func (m *recordingManager) Start(_ context.Context, unit string) error {
	m.calls = append(m.calls, "start "+unit)
	return nil
}

func (m *recordingManager) Stop(_ context.Context, unit string) error {
	m.calls = append(m.calls, "stop "+unit)
	return nil
}

func (m *recordingManager) State(_ context.Context, unit string) (service.UnitState, error) {
	m.calls = append(m.calls, "state "+unit)
	fragment := filepath.Join(m.unitDirectory, unit)
	if m.mainPID != 0 {
		return service.UnitState{Loaded: true, FragmentPath: fragment, Active: "active", Sub: "running", Enabled: m.enabled[unit], MainPID: m.mainPID}, nil
	}
	return service.UnitState{Loaded: true, FragmentPath: fragment, Active: "inactive", Sub: "dead", Enabled: m.enabled[unit]}, nil
}

func serviceTestDependencies(t *testing.T, manager service.Manager, root string) serviceDependencies {
	t.Helper()
	if recorder, ok := manager.(*recordingManager); ok {
		// A loaded unit identifies the exact definition the manager read.
		recorder.unitDirectory = service.UnitDirectory(root)
	}
	payload := filepath.Join(t.TempDir(), "lib", "debuglet", "9.9.9")
	return serviceDependencies{
		root:       root,
		executable: func() (string, error) { return filepath.Join(payload, "bin", "dbl"), nil },
		resolve: func(string) (demo.Assets, error) {
			return demo.Assets{
				Root:       payload,
				CLI:        filepath.Join(payload, "bin", "dbl"),
				Dispatcher: filepath.Join(payload, "bin", "debuglet-dispatcher"),
				Executor:   filepath.Join(payload, "bin", "debuglet-executor"),
				Manifest:   demo.Manifest{SchemaVersion: 1, Version: "9.9.9", SourceSHA: strings.Repeat("a", 40)},
			}, nil
		},
		manager: func(string) (service.Manager, error) { return manager, nil },
		lookup: func(string, string) (service.Account, error) {
			return service.Account{UID: os.Getuid(), GID: os.Getgid()}, nil
		},
		chown: func(*os.File, int, int) error { return nil },
	}
}

func TestServiceCommandRejectsIncompleteRequests(t *testing.T) {
	for name, args := range map[string][]string{
		"no subcommand":     {},
		"unknown operation": {"restart", "--role", "executor"},
		"missing role":      {"status"},
		"unknown role":      {"status", "--role", "guest"},
		"positional":        {"status", "--role", "executor", "extra"},
		"blank name":        {"status", "--role", "executor", "--name", "  "},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := serviceCommandWith(context.Background(), args, globalOptions{Output: outputHuman},
				&stdout, &stderr, serviceTestDependencies(t, newRecordingManager(), t.TempDir()))
			if code != exitUsage {
				t.Fatalf("exit %d, want %d (%s)", code, exitUsage, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("usage error wrote to stdout: %q", stdout.String())
			}
		})
	}
	t.Run("endpoint selection", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := serviceCommandWith(context.Background(), []string{"status", "--role", "executor"},
			globalOptions{Output: outputHuman, EndpointSet: true, Endpoint: "http://127.0.0.1:9000"},
			&stdout, &stderr, serviceTestDependencies(t, newRecordingManager(), t.TempDir()))
		if code != exitUsage {
			t.Fatalf("exit %d, want %d", code, exitUsage)
		}
	})
	t.Run("help", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := serviceCommandWith(context.Background(), []string{"--help"}, globalOptions{Output: outputHuman},
			&stdout, &stderr, serviceTestDependencies(t, newRecordingManager(), t.TempDir()))
		if code != exitOK || !strings.Contains(stdout.String(), "dbl service install") {
			t.Fatalf("help: exit %d %q", code, stdout.String())
		}
	})
}

func TestServiceInstallReportsTheInstalledContract(t *testing.T) {
	root := t.TempDir()
	manager := newRecordingManager()
	deps := serviceTestDependencies(t, manager, root)
	var stdout, stderr bytes.Buffer
	code := serviceCommandWith(context.Background(),
		[]string{"install", "--role", "dispatcher", "--start=false", "--user", "nobody"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var report service.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("install report %q: %v", stdout.String(), err)
	}
	if report.Operation != "install" || report.Unit != "debuglet-dispatcher-local.service" || report.Version != "9.9.9" {
		t.Fatalf("install report: %+v", report)
	}
	if report.State != "installed" || report.Ready {
		t.Fatalf("a service that was not started must not be reported ready: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "systemd", "system", report.Unit)); err != nil {
		t.Fatalf("unit file: %v", err)
	}
	for _, call := range manager.calls {
		if strings.HasPrefix(call, "start ") {
			t.Fatalf("--start=false started the unit: %v", manager.calls)
		}
	}

	// status of the same instance reads the installed record back. A
	// stopped instance is not ready: the report is printed and the exit code
	// says so.
	stdout.Reset()
	code = serviceCommandWith(context.Background(), []string{"status", "--role", "dispatcher"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
	if code != exitNotReady {
		t.Fatalf("status exit %d, want %d: %s", code, exitNotReady, stderr.String())
	}
	var status service.Report
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "stopped" || status.Unit != report.Unit || !status.Enabled {
		t.Fatalf("status report: %+v", status)
	}

	// Running without a readiness record is started, not ready.
	manager.mainPID = 4242
	stdout.Reset()
	code = serviceCommandWith(context.Background(), []string{"status", "--role", "dispatcher"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if code != exitNotReady || status.State != "started" || status.Ready {
		t.Fatalf("status exit %d, report %+v", code, status)
	}

	// Once the running process has published its readiness record, status
	// reports it ready and exits 0.
	paths, err := service.DerivePaths(root, storagecheck.Dispatcher, "local")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.ReadyFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := readiness.Write(paths.ReadyFile, readiness.Record{SchemaVersion: 1, PID: 4242,
		HTTPAddr: "127.0.0.1:9000", GRPCAddr: "127.0.0.1:9001"}); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	code = serviceCommandWith(context.Background(), []string{"status", "--role", "dispatcher"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
	status = service.Report{}
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if code != exitOK || status.State != "ready" || !status.Ready {
		t.Fatalf("status exit %d, report %+v: %s", code, status, stderr.String())
	}
}

func TestServiceInstallRefusalPrintsOnlyTheError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := serviceCommandWith(context.Background(),
		[]string{"install", "--role", "dispatcher", "--start=false", "--user", "nobody", "--port", "9000", "--grpc-port", "9000"},
		globalOptions{Output: outputHuman}, &stdout, &stderr, serviceTestDependencies(t, newRecordingManager(), t.TempDir()))
	if code != exitFailure {
		t.Fatalf("exit %d, want %d", code, exitFailure)
	}
	if strings.Contains(stdout.String(), "(not ready)") {
		t.Fatalf("a refused request printed a summary line: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "ports must be different") {
		t.Fatalf("diagnostic: %q", stderr.String())
	}
}

func TestServicePackageReplacementRequiresExplicitOfflineEnrollment(t *testing.T) {
	base := []string{"install", "--replace-package", "/opt/debuglet/lib/debuglet/2.0.0"}
	enrolled := []string{"--role", "executor", "--enrolled-state", "/var/lib/debuglet/executors/worker"}
	for name, flags := range map[string][]string{
		"dispatcher":                {"--role", "dispatcher", "--enrolled-state", "/var/lib/debuglet/dispatchers/local", "--start=false", "--enable=false"},
		"not enrolled":              {"--role", "executor", "--start=false", "--enable=false"},
		"defaults start and enable": enrolled,
		"missing enable":            append(append([]string{}, enrolled...), "--start=false"),
		"missing start":             append(append([]string{}, enrolled...), "--enable=false"),
		"starts":                    append(append([]string{}, enrolled...), "--start=true", "--enable=false"),
		"enables":                   append(append([]string{}, enrolled...), "--start=false", "--enable=true"),
		"staging":                   append(append([]string{}, enrolled...), "--start=false", "--enable=false", "--root", t.TempDir()),
		"blank target":              append(append([]string{}, enrolled...), "--start=false", "--enable=false", "--replace-package", " "),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			deps := serviceDependencies{
				resolve: func(string) (demo.Assets, error) {
					t.Fatal("invalid replacement resolved a package")
					return demo.Assets{}, nil
				},
				manager: func(string) (service.Manager, error) {
					t.Fatal("invalid replacement reached the manager")
					return nil, nil
				},
			}
			if code := serviceCommandWith(t.Context(), append(append([]string{}, base...), flags...),
				globalOptions{Output: outputHuman}, &stdout, &stderr, deps); code != exitUsage {
				t.Fatalf("exit %d, want usage refusal: %s", code, stderr.String())
			}
		})
	}
}

func TestServicePackageReplacementVerifiesSelectedTarget(t *testing.T) {
	for _, version := range []string{"previous", "candidate"} {
		t.Run(version, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "lib", "debuglet", version)
			if err := os.MkdirAll(target, 0755); err != nil {
				t.Fatal(err)
			}
			manager := newRecordingManager()
			deps := serviceTestDependencies(t, manager, t.TempDir())
			deps.executable = func() (string, error) { t.Fatal("replacement selected the CLI's own package"); return "", nil }
			called := false
			deps.resolve = func(path string) (demo.Assets, error) {
				called = true
				if path != filepath.Join(target, "bin", "dbl") {
					t.Fatalf("resolved %q instead of selected target %q", path, target)
				}
				return demo.Assets{}, errors.New("selected package verification failed")
			}
			var stdout, stderr bytes.Buffer
			code := serviceCommandWith(t.Context(), []string{"install", "--role", "executor",
				"--enrolled-state", "/var/lib/debuglet/executors/worker", "--replace-package", target,
				"--start=false", "--enable=false"}, globalOptions{Output: outputHuman}, &stdout, &stderr, deps)
			if code != exitFailure || !called || !strings.Contains(stderr.String(), "selected package verification failed") {
				t.Fatalf("verification refusal: exit %d, called %v: %s", code, called, stderr.String())
			}
			if len(manager.calls) != 0 || stdout.Len() != 0 {
				t.Fatalf("unverified target reached service actions: %v, output %s", manager.calls, stdout.String())
			}
		})
	}
}

func TestServicePackageReplacementPreservesOmittedAccountOptions(t *testing.T) {
	for name, test := range map[string]struct {
		flags       []string
		user, group string
	}{
		"recorded identity": {},
		"explicit user":     {flags: []string{"--user", "workeruser"}, user: "workeruser"},
		"explicit group":    {flags: []string{"--group", "workergroup"}, group: "workergroup"},
		"explicit identity": {flags: []string{"--user", "workeruser", "--group", "workergroup"}, user: "workeruser", group: "workergroup"},
	} {
		t.Run(name, func(t *testing.T) {
			fs := newCommandFlagSet("service install")
			var local serviceOptions
			serviceFlags(fs, &local, "install")
			args := []string{"--role", "executor", "--enrolled-state", "/var/lib/debuglet/executors/worker",
				"--replace-package", "/opt/debuglet/lib/debuglet/candidate", "--start=false", "--enable=false"}
			if err := fs.Parse(append(args, test.flags...)); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			if _, ok := checkPackageReplacement("dbl service install", &local, fs, &stderr); !ok {
				t.Fatal(stderr.String())
			}
			if local.User != test.user || local.Group != test.group {
				t.Fatalf("account selection %q:%q, want %q:%q", local.User, local.Group, test.user, test.group)
			}
		})
	}
}

func TestServicePackageReplacementDoesNotInstallAMissingInstance(t *testing.T) {
	root := t.TempDir()
	manager := newRecordingManager()
	deps := serviceTestDependencies(t, manager, root)
	assets, err := deps.resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(assets.Root, 0755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := serviceCommandWith(t.Context(), []string{"install", "--role", "executor", "--name", "retained",
		"--enrolled-state", filepath.Join(root, "var", "lib", "debuglet", "executors", "retained"),
		"--replace-package", assets.Root, "--start=false", "--enable=false"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
	var report service.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if code != exitFailure || report.Operation != "replace-package" || report.Name != "retained" {
		t.Fatalf("replacement route: exit %d, report %+v, error %s", code, report, stderr.String())
	}
	if _, err := os.Stat(service.RecordPath(root, storagecheck.Executor, "retained")); !os.IsNotExist(err) {
		t.Fatalf("replacement created an installation record: %v", err)
	}
	if len(manager.calls) != 0 {
		t.Fatalf("missing instance reached the manager: %v", manager.calls)
	}
}

func TestServicePackageReplacementRejectsRedirectedExecutable(t *testing.T) {
	manager := newRecordingManager()
	deps := serviceTestDependencies(t, manager, t.TempDir())
	assets, err := deps.resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(assets.CLI), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assets.CLI, []byte("fixture CLI"), 0755); err != nil {
		t.Fatal(err)
	}
	requested := t.TempDir()
	if err := os.Mkdir(filepath.Join(requested, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(assets.CLI, filepath.Join(requested, "bin", "dbl")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := serviceCommandWith(t.Context(), []string{"install", "--role", "executor",
		"--enrolled-state", "/var/lib/debuglet/executors/worker", "--replace-package", requested,
		"--start=false", "--enable=false"}, globalOptions{Output: outputHuman}, &stdout, &stderr, deps)
	if code != exitFailure || !strings.Contains(stderr.String(), "resolves to another package") {
		t.Fatalf("redirected target: exit %d, error %s", code, stderr.String())
	}
	if stdout.Len() != 0 || len(manager.calls) != 0 {
		t.Fatalf("redirected target reached service actions: %s, %v", stdout.String(), manager.calls)
	}
	alias := filepath.Join(t.TempDir(), "package")
	if err := os.Symlink(assets.Root, alias); err != nil {
		t.Fatal(err)
	}
	selected, err := resolveReplacementAssets(alias, deps)
	if err != nil || selected.Root != assets.Root {
		t.Fatalf("valid directory alias refused: %+v, %v", selected, err)
	}
}

func TestServiceStatusOfAnUninstalledInstanceFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := serviceCommandWith(context.Background(),
		[]string{"status", "--role", "executor"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, serviceTestDependencies(t, newRecordingManager(), t.TempDir()))
	if code != exitFailure {
		t.Fatalf("exit %d, want %d", code, exitFailure)
	}
	var report service.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("report %q: %v", stdout.String(), err)
	}
	if report.State != "not-installed" {
		t.Fatalf("report: %+v", report)
	}
	if !strings.Contains(stderr.String(), "no managed executor") {
		t.Fatalf("diagnostic: %q", stderr.String())
	}
}

func TestDrainCommandRejectsIncompleteRequests(t *testing.T) {
	for name, args := range map[string][]string{
		"missing role":    {},
		"unknown role":    {"--role", "guest"},
		"positional":      {"--role", "executor", "extra"},
		"zero wait":       {"--role", "executor", "--wait", "0s"},
		"resume with why": {"--role", "dispatcher", "--resume", "--reason", "planned"},
		// A dispatcher is not stopped, so there is no unit to leave
		// startable and nothing for this option to mean.
		"dispatcher keep-enabled": {"--role", "dispatcher", "--keep-enabled"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := drainCommandWith(context.Background(), args, globalOptions{Output: outputHuman},
				&stdout, &stderr, serviceTestDependencies(t, newRecordingManager(), t.TempDir()))
			if code != exitUsage {
				t.Fatalf("exit %d, want %d (%s)", code, exitUsage, stderr.String())
			}
		})
	}
}

func TestDrainDispatcherStopsAdmissionWithoutStoppingIt(t *testing.T) {
	root := t.TempDir()
	manager := newRecordingManager()
	deps := serviceTestDependencies(t, manager, root)
	var stdout, stderr bytes.Buffer
	if code := serviceCommandWith(context.Background(),
		[]string{"install", "--role", "dispatcher", "--start=false", "--user", "nobody"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, deps); code != exitOK {
		t.Fatalf("install exit %d: %s", code, stderr.String())
	}
	stdout.Reset()
	code := drainCommandWith(context.Background(), []string{"--role", "dispatcher", "--reason", "planned"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
	if code != exitOK {
		t.Fatalf("drain exit %d: %s", code, stderr.String())
	}
	var report service.DrainReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("drain report %q: %v", stdout.String(), err)
	}
	if report.Outcome != "paused" || report.Joined {
		t.Fatalf("drain report: %+v", report)
	}
	for _, call := range manager.calls {
		if strings.HasPrefix(call, "stop ") {
			t.Fatalf("draining a dispatcher stopped it: %v", manager.calls)
		}
	}
	switchPath := filepath.Join(root, "etc", "debuglet", "services", "dispatcher-local.maintenance")
	state, err := service.ReadMaintenance(switchPath)
	if err != nil || !state.Paused || state.Reason != "planned" {
		t.Fatalf("maintenance switch: %+v %v", state, err)
	}
	stdout.Reset()
	if code := drainCommandWith(context.Background(), []string{"--role", "dispatcher", "--resume"},
		globalOptions{Output: outputHuman}, &stdout, &stderr, deps); code != exitOK {
		t.Fatalf("resume exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "resumed") {
		t.Fatalf("resume output: %q", stdout.String())
	}
	if _, err := os.Stat(switchPath); !os.IsNotExist(err) {
		t.Fatalf("the maintenance switch survived the resume: %v", err)
	}
}

// A staged tree is files only. The host has one service manager, and a unit of
// the same name there is the production instance, so nothing staged may reach
// it: not a start, not a stop, not even a state query.
func TestAStagingRootNeverReachesTheServiceManager(t *testing.T) {
	staged := t.TempDir()
	for name, args := range map[string][]string{
		"start":     {"start", "--role", "executor", "--root", staged},
		"stop":      {"stop", "--role", "executor", "--root", staged},
		"uninstall": {"uninstall", "--role", "executor", "--root", staged},
		"install starting": {"install", "--role", "dispatcher", "--root", staged,
			"--start=true", "--user", "nobody"},
		"install enabling": {"install", "--role", "dispatcher", "--root", staged,
			"--start=false", "--enable=true", "--user", "nobody"},
	} {
		t.Run(name, func(t *testing.T) {
			manager := newRecordingManager()
			var stdout, stderr bytes.Buffer
			code := serviceCommandWith(context.Background(), args, globalOptions{Output: outputHuman},
				&stdout, &stderr, serviceTestDependencies(t, manager, ""))
			if code != exitUsage {
				t.Fatalf("exit %d, want %d (%s)", code, exitUsage, stderr.String())
			}
			if len(manager.calls) != 0 {
				t.Fatalf("a staged operation reached the service manager: %v", manager.calls)
			}
		})
	}
	t.Run("drain", func(t *testing.T) {
		manager := newRecordingManager()
		var stdout, stderr bytes.Buffer
		code := drainCommandWith(context.Background(), []string{"--role", "executor", "--root", staged},
			globalOptions{Output: outputHuman}, &stdout, &stderr, serviceTestDependencies(t, manager, ""))
		if code != exitUsage || len(manager.calls) != 0 {
			t.Fatalf("staged drain: exit %d calls %v (%s)", code, manager.calls, stderr.String())
		}
	})
	t.Run("staging installs write files and drive nothing", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		deps := serviceTestDependencies(t, newRecordingManager(), "")
		// The command picks its own manager from the root it parsed; the
		// one this test supplies is exactly what must not be used.
		deps.manager = productionServiceDependencies().manager
		code := serviceCommandWith(context.Background(),
			[]string{"install", "--role", "dispatcher", "--root", staged, "--user", "nobody"},
			globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
		if code != exitOK {
			t.Fatalf("staged install: exit %d (%s)", code, stderr.String())
		}
		var report service.Report
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Ready || report.Enabled || slicesContainsString(report.Changed, "started") {
			t.Fatalf("a staged install claimed a running service: %+v", report)
		}
		if _, err := os.Stat(filepath.Join(staged, "etc", "systemd", "system", report.Unit)); err != nil {
			t.Fatalf("staged unit: %v", err)
		}
	})
	t.Run("the manager of a staged root refuses every action", func(t *testing.T) {
		manager, err := productionServiceDependencies().manager(staged)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := manager.(service.StagingManager); !ok {
			t.Fatalf("a staged root uses %T", manager)
		}
		for name, act := range map[string]func() error{
			"start":   func() error { return manager.Start(context.Background(), "u.service") },
			"stop":    func() error { return manager.Stop(context.Background(), "u.service") },
			"enable":  func() error { return manager.Enable(context.Background(), "u.service") },
			"disable": func() error { return manager.Disable(context.Background(), "u.service") },
		} {
			if err := act(); !errors.Is(err, service.ErrStagingRoot) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// Nothing was loaded from a staged tree, so there is nothing to
		// re-read and nothing to refuse.
		if err := manager.Reload(context.Background()); err != nil {
			t.Fatalf("reload: %v", err)
		}
		state, err := manager.State(context.Background(), "u.service")
		if err != nil || state.Loaded || state.Running() {
			t.Fatalf("a staged unit is not loaded: %+v %v", state, err)
		}
	})
}

func slicesContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestPruneReportNamesPackageWithoutDaemonReadiness(t *testing.T) {
	var out bytes.Buffer
	err := writeServiceReport(&out, service.Report{Operation: "prune", Version: "v0.1.0", State: "pruned", PackagePath: "/opt/debuglet/lib/debuglet/v0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "prune v0.1.0: pruned") || !strings.Contains(out.String(), "package: /opt/debuglet/lib/debuglet/v0.1.0") || strings.Contains(out.String(), "ready") {
		t.Fatalf("misleading package report: %s", out.String())
	}
}

func TestPruneDoesNotResolveServiceManager(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := serviceDependencies{manager: func(string) (service.Manager, error) {
		t.Fatal("prune tried to resolve the service manager")
		return nil, errors.New("unexpected manager lookup")
	}}
	code := serviceCommandWith(t.Context(), []string{"prune", "--prefix", t.TempDir(), "--version", "v0.1.0"},
		globalOptions{Output: outputHuman}, &stdout, &stderr, deps)
	if code != exitFailure || (!strings.Contains(stderr.String(), "no such file") && !strings.Contains(stderr.String(), "administrator access")) {
		t.Fatalf("expected filesystem or permission refusal, got %d: %s", code, stderr.String())
	}
}
