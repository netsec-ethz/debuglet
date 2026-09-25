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
)

// recordingManager is the command's view of a service manager: enough to check
// that the command drives one unit and reports what it read back, without a
// live manager. Readiness itself is covered where it is implemented, in
// internal/demo/service.
type recordingManager struct {
	calls   []string
	enabled map[string]bool
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
	return service.UnitState{Loaded: true, Active: "inactive", Sub: "dead", Enabled: m.enabled[unit]}, nil
}

func serviceTestDependencies(t *testing.T, manager service.Manager, root string) serviceDependencies {
	t.Helper()
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

	// status of the same instance reads the installed record back.
	stdout.Reset()
	code = serviceCommandWith(context.Background(), []string{"status", "--role", "dispatcher"},
		globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
	if code != exitOK {
		t.Fatalf("status exit %d: %s", code, stderr.String())
	}
	var status service.Report
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "stopped" || status.Unit != report.Unit || !status.Enabled {
		t.Fatalf("status report: %+v", status)
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
