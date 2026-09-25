package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/pelletier/go-toml/v2"
)

const (
	testVersion = "1.4.2"
	testSHA     = "0123456789abcdef0123456789abcdef01234567"
)

type fixture struct {
	t         *testing.T
	root      string
	manager   *fakeManager
	installer *Installer
	assets    demo.Assets
	chowned   map[string]Account
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	payload := filepath.Join(root, "usr", "local", "lib", "debuglet", testVersion)
	f := &fixture{
		t: t, root: root, manager: newFakeManager(t, root), chowned: map[string]Account{},
		assets: demo.Assets{
			Root:       payload,
			CLI:        filepath.Join(payload, "bin", "dbl"),
			Dispatcher: filepath.Join(payload, "bin", "debuglet-dispatcher"),
			Executor:   filepath.Join(payload, "bin", "debuglet-executor"),
			Manifest:   demo.Manifest{SchemaVersion: 1, Version: testVersion, SourceSHA: testSHA},
		},
	}
	installer, err := New(Options{
		Root: root, Manager: f.manager, ReadyTimeout: 2 * time.Second, StopTimeout: time.Second,
		LookupAccount: func(user, group string) (Account, error) {
			if user != DefaultAccount && user != "debuglet-alt" {
				return Account{}, errors.New("no such account: " + user)
			}
			return Account{UID: 4242, GID: 4343}, nil
		},
		Chown: func(file *os.File, uid, gid int) error {
			// The walk names the directory itself "."; clean the joined
			// name so the recorded key is the path the tests use.
			f.chowned[filepath.Clean(file.Name())] = Account{UID: uid, GID: gid}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.installer = installer
	return f
}

func (f *fixture) install(role demo.SchemaRole, name string, start bool) (Report, error) {
	f.t.Helper()
	request := Request{Role: role, Name: name}
	if role == demo.ExecutorSchema {
		request.DispatcherGRPC, request.DispatcherHTTP = "127.0.0.1:9001", "127.0.0.1:9000"
	}
	return f.installer.Install(context.Background(), request, f.assets, start, true)
}

func (f *fixture) readyFile(role demo.SchemaRole, name string) string {
	f.t.Helper()
	return filepath.Join(f.root, "run", "debuglet", string(role)+"s", name, "ready.json")
}

func (f *fixture) unitText(role demo.SchemaRole, name string) string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(UnitDirectory(f.root), UnitName(role, name)))
	if err != nil {
		f.t.Fatalf("read generated unit: %v", err)
	}
	return string(data)
}

func TestInstallIsRepeatableAndStartsOnlyTheRequestedRole(t *testing.T) {
	f := newFixture(t)
	report, err := f.install(demo.DispatcherSchema, "local", true)
	if err != nil {
		t.Fatalf("install dispatcher: %v", err)
	}
	if report.State != "ready" || !report.Ready || !report.Enabled {
		t.Fatalf("first install report: %+v", report)
	}
	if report.Endpoint != "http://127.0.0.1:9000" {
		t.Fatalf("dispatcher endpoint: %q", report.Endpoint)
	}
	for _, want := range []string{"state directory", "database", "configuration", "unit", "enabled", "started"} {
		if !slicesContains(report.Changed, want) {
			t.Fatalf("first install changed %v, want %s", report.Changed, want)
		}
	}
	// The unit has to start the verified payload of this exact version and
	// serve the persistent state directory, or a restart would not keep the
	// databases the installation just created.
	unit := f.unitText(demo.DispatcherSchema, "local")
	stateDir := StateDirectory(f.root, demo.DispatcherSchema, "local")
	for _, want := range []string{
		filepath.Join(f.assets.Root, "bin", "debuglet-dispatcher"),
		"-config " + filepath.Join(stateDir, "service.toml"),
		"-ready-file " + filepath.Join(f.root, "run", "debuglet", "dispatchers", "local", "ready.json"),
		"Restart=on-failure",
		"SyslogIdentifier=debuglet-dispatcher\n",
		"ReadWritePaths=" + stateDir,
		"TimeoutStopSec=45",
		"User=" + DefaultAccount,
		MaintenanceFileEnv + "=" + filepath.Join(AdministrationDirectory(f.root), "dispatcher-local.maintenance"),
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("generated unit lacks %q:\n%s", want, unit)
		}
	}
	if !strings.Contains(unit, "/lib/debuglet/"+testVersion+"/") {
		t.Fatalf("generated unit does not pin the verified version:\n%s", unit)
	}
	// The whole state directory belongs to the service account.
	if owner, ok := f.chowned[stateDir]; !ok || owner.UID != 4242 || owner.GID != 4343 {
		t.Fatalf("state directory ownership: %+v (%v)", owner, ok)
	}
	if info, err := os.Lstat(stateDir); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("state directory mode: %v %v", info, err)
	}
	// The installed record is not in that directory and is not handed to
	// the account: it tells later privileged commands where to act.
	record := RecordPath(f.root, demo.DispatcherSchema, "local")
	if strings.HasPrefix(record, stateDir) {
		t.Fatalf("the installed record is inside the account's directory: %s", record)
	}
	if _, owned := f.chowned[record]; owned {
		t.Fatalf("the installed record was handed to the service account")
	}
	info, err := os.Lstat(record)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		t.Fatalf("installed record: %v %v", info, err)
	}

	// A second identical install is a complete no-op apart from reading.
	before := f.manager.recorded()
	again, err := f.install(demo.DispatcherSchema, "local", true)
	if err != nil {
		t.Fatalf("repeat install: %v", err)
	}
	if len(again.Changed) != 0 || !again.Ready || again.RestartRequired {
		t.Fatalf("repeat install report: %+v", again)
	}
	for _, call := range f.manager.recorded()[len(before):] {
		if !strings.HasPrefix(call, "state ") {
			t.Fatalf("repeat install called %q", call)
		}
	}

	// Installing the executor starts only the executor.
	dispatcherUnitBefore := f.unitText(demo.DispatcherSchema, "local")
	mark := len(f.manager.recorded())
	executor, err := f.install(demo.ExecutorSchema, "worker", true)
	if err != nil {
		t.Fatalf("install executor: %v", err)
	}
	if executor.ExecutorID == "" || !executor.Ready || executor.Endpoint != "" {
		t.Fatalf("executor install report: %+v", executor)
	}
	for _, call := range f.manager.recorded()[mark:] {
		if strings.HasSuffix(call, UnitName(demo.DispatcherSchema, "local")) && !strings.HasPrefix(call, "state ") {
			t.Fatalf("installing the executor acted on the dispatcher: %q", call)
		}
	}
	if f.unitText(demo.DispatcherSchema, "local") != dispatcherUnitBefore {
		t.Fatal("installing the executor rewrote the dispatcher unit")
	}
	if state, _ := f.manager.State(context.Background(), UnitName(demo.DispatcherSchema, "local")); !state.Running() {
		t.Fatalf("the dispatcher stopped serving: %+v", state)
	}
}

func TestInstallRefusesAnUnmanagedUnitBeforeWritingState(t *testing.T) {
	for _, role := range []demo.SchemaRole{demo.DispatcherSchema, demo.ExecutorSchema} {
		t.Run(string(role), func(t *testing.T) {
			f := newFixture(t)
			unit := filepath.Join(UnitDirectory(f.root), UnitName(role, "local"))
			if err := os.MkdirAll(filepath.Dir(unit), 0755); err != nil {
				t.Fatal(err)
			}
			const original = "[Service]\nExecStart=/opt/existing-service\n"
			if err := os.WriteFile(unit, []byte(original), 0640); err != nil {
				t.Fatal(err)
			}
			report, err := f.install(role, "local", true)
			if err == nil || !strings.Contains(err.Error(), "unmanaged unit "+unit) {
				t.Fatalf("unmanaged unit was not refused: %+v %v", report, err)
			}
			if data, err := os.ReadFile(unit); err != nil || string(data) != original {
				t.Fatalf("existing unit changed: %q %v", data, err)
			}
			if info, err := os.Stat(unit); err != nil || info.Mode().Perm() != 0640 {
				t.Fatalf("existing unit mode changed: %v %v", info, err)
			}
			for _, path := range []string{StateDirectory(f.root, role, "local"), RecordPath(f.root, role, "local")} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("refused installation created %s: %v", path, err)
				}
			}
			if calls := f.manager.recorded(); len(calls) != 0 {
				t.Fatalf("refused installation called the service manager: %v", calls)
			}
			if len(report.Changed) != 0 || len(f.chowned) != 0 {
				t.Fatalf("refused installation changed state: %+v, ownership %v", report, f.chowned)
			}
		})
	}
}

func TestManagedRestartPreservesDatabaseAndIdentity(t *testing.T) {
	f := newFixture(t)
	first, err := f.install(demo.ExecutorSchema, "worker", true)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	stateDir := StateDirectory(f.root, demo.ExecutorSchema, "worker")
	database := filepath.Join(stateDir, "executor.sqlite")
	info, err := os.Stat(database)
	if err != nil {
		t.Fatalf("stat database: %v", err)
	}
	if _, err := f.installer.Stop(context.Background(), demo.ExecutorSchema, "worker"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// The readiness record is withdrawn by the daemon, so nothing claims a
	// stopped executor is ready.
	if status, err := f.installer.Status(context.Background(), demo.ExecutorSchema, "worker"); err != nil || status.Ready {
		t.Fatalf("status after stop: %+v %v", status, err)
	}
	restarted, err := f.installer.Start(context.Background(), demo.ExecutorSchema, "worker")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !restarted.Ready || restarted.ExecutorID != first.ExecutorID || first.ExecutorID == "" {
		t.Fatalf("restart changed identity: %q -> %q", first.ExecutorID, restarted.ExecutorID)
	}
	after, err := os.Stat(database)
	if err != nil {
		t.Fatalf("database after restart: %v", err)
	}
	if !os.SameFile(info, after) {
		t.Fatal("the restart replaced the executor database")
	}
	// The published record names the restarted process and the retained
	// identity, which is what makes the readiness observation meaningful.
	record, err := os.ReadFile(filepath.Join(f.root, "run", "debuglet", "executors", "worker", "ready.json"))
	if err != nil {
		t.Fatalf("read readiness record: %v", err)
	}
	var published struct {
		PID        int    `json:"pid"`
		ExecutorID string `json:"executor_id"`
	}
	if err := json.Unmarshal(record, &published); err != nil {
		t.Fatal(err)
	}
	if published.ExecutorID != first.ExecutorID || published.PID != restarted.MainPID {
		t.Fatalf("published readiness %+v does not match report %+v", published, restarted)
	}
}

func TestReadinessIsObservedNotInferred(t *testing.T) {
	t.Run("a started process that never reports ready is not ready", func(t *testing.T) {
		f := newFixture(t)
		f.manager.silent = true
		report, err := f.install(demo.DispatcherSchema, "local", true)
		if err == nil {
			t.Fatal("install reported success without a readiness record")
		}
		if report.State != "incomplete" || report.Ready {
			t.Fatalf("silent daemon report: %+v", report)
		}
		if report.Active != "active" {
			t.Fatalf("the unit was expected to be running but not ready: %+v", report)
		}
	})
	t.Run("a record from another process is not accepted", func(t *testing.T) {
		f := newFixture(t)
		if _, err := f.install(demo.ExecutorSchema, "worker", true); err != nil {
			t.Fatalf("install: %v", err)
		}
		ready := filepath.Join(f.root, "run", "debuglet", "executors", "worker", "ready.json")
		data, err := os.ReadFile(ready)
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		record["pid"] = 999999
		stale, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ready, stale, 0600); err != nil {
			t.Fatal(err)
		}
		status, err := f.installer.Status(context.Background(), demo.ExecutorSchema, "worker")
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if status.Ready || status.State != "started" || status.Note == "" {
			t.Fatalf("a foreign readiness record was accepted: %+v", status)
		}
	})
}

func TestUninstallKeepsStateAndPurgeNeedsAJoin(t *testing.T) {
	f := newFixture(t)
	if _, err := f.install(demo.ExecutorSchema, "worker", true); err != nil {
		t.Fatalf("install: %v", err)
	}
	stateDir := StateDirectory(f.root, demo.ExecutorSchema, "worker")
	unitPath := filepath.Join(UnitDirectory(f.root), UnitName(demo.ExecutorSchema, "worker"))

	// A daemon that was killed at its stop timeout never finished its own
	// shutdown, so nothing may be deleted on the strength of it, and the
	// readiness record being gone says nothing: the runtime directory is
	// removed whenever the unit stops.
	f.manager.timedOut = true
	report, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", true)
	if err == nil {
		t.Fatal("purge succeeded without proof that the daemon released its state")
	}
	if report.State != "incomplete" || report.Note == "" {
		t.Fatalf("purge report: %+v", report)
	}
	if _, err := os.Stat(f.readyFile(demo.ExecutorSchema, "worker")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the runtime directory outlived the stop: %v", err)
	}
	for _, undone := range []string{"unit", "disabled", "state directory"} {
		if slicesContains(report.Changed, undone) {
			t.Fatalf("a refused purge changed %q: %+v", undone, report.Changed)
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, "executor.sqlite")); err != nil {
		t.Fatalf("a refused purge removed state: %v", err)
	}
	if _, err := os.Stat(unitPath); err != nil {
		t.Fatalf("a refused purge removed the unit: %v", err)
	}

	// A unit that is down may always be removed and disabled: that touches
	// no state. The state itself still needs the proof, which this daemon
	// never gave, so it is kept.
	unfinished, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", false)
	if err != nil {
		t.Fatalf("uninstall after a failed shutdown: %v", err)
	}
	if unfinished.Joined || unfinished.Note == "" || !slicesContains(unfinished.Changed, "unit") {
		t.Fatalf("uninstall after a failed shutdown: %+v", unfinished)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "executor.sqlite")); err != nil {
		t.Fatalf("uninstall removed the database: %v", err)
	}

	// A failed unit stays failed until it is started and stopped again, so
	// deleting its state stays refused until a daemon actually finished.
	if _, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", true); err == nil {
		t.Fatal("state was deleted while the last shutdown was still unfinished")
	}
	f.manager.timedOut = false
	if _, err := f.install(demo.ExecutorSchema, "worker", true); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	kept, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", false)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if kept.State != "uninstalled" || kept.Enabled || !kept.Joined || !slicesContains(kept.Changed, "unit") {
		t.Fatalf("uninstall report: %+v", kept)
	}
	if _, err := os.Stat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit file survived uninstall: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "executor.sqlite")); err != nil {
		t.Fatalf("uninstall removed the database: %v", err)
	}
	// Uninstalling again changes nothing and still succeeds.
	repeat, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", false)
	if err != nil {
		t.Fatalf("repeated uninstall: %v", err)
	}
	if len(repeat.Changed) != 0 {
		t.Fatalf("repeated uninstall changed %v", repeat.Changed)
	}
	purged, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", true)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purge kept the state directory: %v", err)
	}
	if !slicesContains(purged.Changed, "state directory") || !slicesContains(purged.Changed, "installed record") {
		t.Fatalf("purge report: %+v", purged)
	}
	if _, err := os.Stat(RecordPath(f.root, demo.ExecutorSchema, "worker")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purge kept the installed record: %v", err)
	}
}

// TestGeneratedUnitMatchesReference keeps deploy/systemd honest: the reference
// units an operator reads are exactly what this package writes.
func TestGeneratedUnitMatchesReference(t *testing.T) {
	const version = "0.0.0-reference"
	payload := "/usr/local/lib/debuglet/" + version
	assets := demo.Assets{
		Root: payload, CLI: payload + "/bin/dbl",
		Dispatcher: payload + "/bin/debuglet-dispatcher",
		Executor:   payload + "/bin/debuglet-executor",
		Manifest:   demo.Manifest{SchemaVersion: 1, Version: version, SourceSHA: testSHA},
	}
	for _, tc := range []struct {
		role      demo.SchemaRole
		name      string
		reference string
	}{
		{demo.DispatcherSchema, "local", "debuglet-dispatcher-local.service"},
		{demo.ExecutorSchema, "worker", "debuglet-executor-worker.service"},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			request := Request{Role: tc.role, Name: tc.name, Root: "/"}
			p, err := Resolve(request, assets)
			if err != nil {
				t.Fatal(err)
			}
			text, err := Unit(p)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "systemd", tc.reference))
			if err != nil {
				t.Fatal(err)
			}
			if text != string(want) {
				t.Fatalf("generated unit differs from deploy/systemd/%s\n--- generated ---\n%s\n--- reference ---\n%s", tc.reference, text, want)
			}
		})
	}
}

func TestResolveRefusesProfilesItCannotHonor(t *testing.T) {
	payload := "/usr/local/lib/debuglet/1.0.0"
	assets := demo.Assets{Root: payload, Dispatcher: payload + "/bin/debuglet-dispatcher",
		Executor: payload + "/bin/debuglet-executor",
		Manifest: demo.Manifest{Version: "1.0.0", SourceSHA: testSHA}}
	for name, request := range map[string]Request{
		"unknown role":        {Role: "guest", Name: "local"},
		"invalid name":        {Role: demo.DispatcherSchema, Name: "../escape"},
		"relative root":       {Role: demo.DispatcherSchema, Name: "local", Root: "relative"},
		"equal ports":         {Role: demo.DispatcherSchema, Name: "local", HTTPPort: 9000, GRPCPort: 9000},
		"remote dispatcher":   {Role: demo.ExecutorSchema, Name: "worker", DispatcherGRPC: "example.com:9001"},
		"nonloopback address": {Role: demo.ExecutorSchema, Name: "worker", DispatcherGRPC: "192.0.2.1:9001"},
		"invalid account":     {Role: demo.DispatcherSchema, Name: "local", User: "Root User"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Resolve(request, assets); err == nil {
				t.Fatal("accepted a profile this package cannot honor")
			}
		})
	}
	// A package installed in a home directory is refused before anything is
	// written: the unit hides home directories from the service.
	for _, root := range []string{"/home/operator/.local/lib/debuglet/1.0.0", "/root/lib/debuglet/1.0.0"} {
		home := demo.Assets{Root: root, Dispatcher: root + "/bin/debuglet-dispatcher",
			Manifest: demo.Manifest{Version: "1.0.0", SourceSHA: testSHA}}
		if _, err := Resolve(Request{Role: demo.DispatcherSchema, Name: "local", Root: "/"}, home); err == nil {
			t.Fatalf("a payload under %s was accepted", root)
		}
	}
	// A payload path a unit file cannot carry literally is refused before
	// anything is written, rather than escaped by this renderer.
	spaced := demo.Assets{Root: "/opt/deb uglet", Dispatcher: "/opt/deb uglet/bin/debuglet-dispatcher",
		Manifest: demo.Manifest{Version: "1.0.0", SourceSHA: testSHA}}
	p, err := Resolve(Request{Role: demo.DispatcherSchema, Name: "local", Root: "/"}, spaced)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unit(p); err == nil {
		t.Fatal("a path with a space was rendered into a unit")
	}
}

func slicesContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// A record inside the account's own directory would let a daemon tell the next
// privileged command where to act. The record lives outside that directory for
// exactly that reason, and it is believed only where it agrees with the paths
// derived from the root, role and name an operator named.
func TestARecordThatDisagreesWithItsInstanceIsRefused(t *testing.T) {
	f := newFixture(t)
	if _, err := f.install(demo.ExecutorSchema, "worker", true); err != nil {
		t.Fatalf("install: %v", err)
	}
	decoy := filepath.Join(f.root, "decoy")
	if err := os.MkdirAll(filepath.Join(decoy, "keep"), 0700); err != nil {
		t.Fatal(err)
	}
	decoyUnit := filepath.Join(f.root, "etc", "systemd", "system", "unrelated.service")
	if err := os.WriteFile(decoyUnit, []byte("[Unit]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	record := RecordPath(f.root, demo.ExecutorSchema, "worker")
	for name, tamper := range map[string]func(map[string]any){
		"state directory": func(fields map[string]any) { fields["state_dir"] = decoy },
		"unit file":       func(fields map[string]any) { fields["unit_path"] = decoyUnit },
		"runtime":         func(fields map[string]any) { fields["runtime_dir"] = decoy },
		"database":        func(fields map[string]any) { fields["database_path"] = filepath.Join(decoy, "keep") },
		"switch":          func(fields map[string]any) { fields["maintenance_file"] = filepath.Join(decoy, "keep") },
		"identity":        func(fields map[string]any) { fields["name"] = "elsewhere" },
		"root":            func(fields map[string]any) { fields["root"] = decoy },
	} {
		t.Run(name, func(t *testing.T) {
			original, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.WriteFile(record, original, 0644); err != nil {
					t.Fatal(err)
				}
			})
			var fields map[string]any
			if err := json.Unmarshal(original, &fields); err != nil {
				t.Fatal(err)
			}
			tamper(fields)
			rewritten, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(record, rewritten, 0644); err != nil {
				t.Fatal(err)
			}
			for operation, run := range map[string]func() error{
				"install": func() error {
					_, err := f.install(demo.ExecutorSchema, "worker", true)
					return err
				},
				"status": func() error {
					_, err := f.installer.Status(context.Background(), demo.ExecutorSchema, "worker")
					return err
				},
				"stop": func() error {
					_, err := f.installer.Stop(context.Background(), demo.ExecutorSchema, "worker")
					return err
				},
				"purge": func() error {
					_, err := f.installer.Uninstall(context.Background(), demo.ExecutorSchema, "worker", true)
					return err
				},
				"drain": func() error {
					_, err := f.installer.Drain(context.Background(), demo.ExecutorSchema, "worker", DrainOptions{Timeout: time.Second})
					return err
				},
				"resume": func() error {
					_, err := f.installer.Resume(context.Background(), demo.ExecutorSchema, "worker")
					return err
				},
			} {
				if err := run(); err == nil {
					t.Fatalf("%s accepted a record that does not describe this instance", operation)
				}
			}
			for _, kept := range []string{filepath.Join(decoy, "keep"), decoyUnit} {
				if _, err := os.Stat(kept); err != nil {
					t.Fatalf("a refused operation touched %s: %v", kept, err)
				}
			}
		})
	}
}

// The account owns its state directory between installations, so it can put
// anything in it. Nothing there may redirect the ownership an installation
// applies: this runs the real ownership syscalls on a real tree.
func TestOwnershipRefusesAnythingButFilesAndDirectories(t *testing.T) {
	f := newOwningFixture(t)
	if _, err := f.install(demo.ExecutorSchema, "worker", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	outside := filepath.Join(f.root, "outside")
	if err := os.WriteFile(outside, []byte("host file"), 0644); err != nil {
		t.Fatal(err)
	}
	stateDir := StateDirectory(f.root, demo.ExecutorSchema, "worker")
	link := filepath.Join(stateDir, "redirect")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	report, err := f.install(demo.ExecutorSchema, "worker", false)
	if err == nil {
		t.Fatalf("a symbolic link in the state directory was followed: %+v", report)
	}
	if !strings.Contains(err.Error(), link) {
		t.Fatalf("the refusal does not name the entry: %v", err)
	}
	info, err := os.Lstat(outside)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("the link's target was changed: %v %v", info, err)
	}
	if target, err := os.Readlink(link); err != nil || target != outside {
		t.Fatalf("the link itself changed: %q %v", target, err)
	}
}

// newOwningFixture is a fixture whose installer runs the real ownership
// syscalls with an account this test may apply.
func newOwningFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	installer, err := New(Options{
		Root: f.root, Manager: f.manager, ReadyTimeout: 2 * time.Second, StopTimeout: time.Second,
		LookupAccount: func(string, string) (Account, error) {
			return Account{UID: os.Getuid(), GID: os.Getgid()}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.installer = installer
	return f
}

// A link whose target stays inside the state directory is the one the confined
// walk would otherwise follow: it never leaves the root, so the descriptor the
// directory hands back resolves it. It is refused as well, because ownership
// belongs to the entries this installation made and not to a second name the
// account invented for one of them.
func TestOwnershipRefusesALinkThatStaysInsideTheStateDirectory(t *testing.T) {
	f := newOwningFixture(t)
	if _, err := f.install(demo.ExecutorSchema, "worker", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	stateDir := StateDirectory(f.root, demo.ExecutorSchema, "worker")
	inside := filepath.Join(stateDir, "inside")
	if err := os.WriteFile(inside, []byte("service state"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(stateDir, "redirect")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	report, err := f.install(demo.ExecutorSchema, "worker", false)
	if err == nil {
		t.Fatalf("a link inside the state directory was followed: %+v", report)
	}
	if !strings.Contains(err.Error(), link) {
		t.Fatalf("the refusal does not name the entry: %v", err)
	}
	if target, err := os.Readlink(link); err != nil || target != inside {
		t.Fatalf("the link itself changed: %q %v", target, err)
	}
}

// Refusing a symbolic link that is already there is not enough: the account
// owns this directory while the ownership is being applied, so it can replace
// an entry after it was read and before it is used. Nothing here resolves a
// name twice, so the swap below reaches neither the mode of a host directory
// nor the files inside it. The ownership seam supplies the swap at exactly the
// moment the walk has the entry in hand, which is the whole window.
func TestOwnershipDoesNotFollowAnEntrySwappedAfterItWasRead(t *testing.T) {
	f := newFixture(t)
	stateDir := StateDirectory(f.root, demo.ExecutorSchema, "worker")
	swapped := filepath.Join(stateDir, "sub")
	victim := filepath.Join(f.root, "victim")
	if err := os.MkdirAll(filepath.Join(victim, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(victim, "secret")
	if err := os.WriteFile(secret, []byte("host state"), 0644); err != nil {
		t.Fatal(err)
	}
	installer, err := New(Options{
		Root: f.root, Manager: f.manager, ReadyTimeout: 2 * time.Second, StopTimeout: time.Second,
		LookupAccount: func(string, string) (Account, error) {
			return Account{UID: os.Getuid(), GID: os.Getgid()}, nil
		},
		// The real fchown and fchmod, with an account this test may apply,
		// and the swap performed while the walk holds the entry.
		Chown: func(file *os.File, uid, gid int) error {
			if filepath.Clean(file.Name()) == swapped {
				if err := os.RemoveAll(swapped); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, swapped); err != nil {
					t.Fatal(err)
				}
			}
			return file.Chown(uid, gid)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.installer = installer
	if _, err := f.install(demo.ExecutorSchema, "worker", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	// The account created these between the two installations, which is what
	// it is allowed to do with its own directory.
	if err := os.Mkdir(swapped, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(swapped, "kept"), []byte("service state"), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := f.install(demo.ExecutorSchema, "worker", false)
	if err == nil {
		t.Fatalf("a replaced directory entry was followed: %+v", report)
	}
	if !strings.Contains(err.Error(), swapped) {
		t.Fatalf("the refusal does not name the entry: %v", err)
	}
	for path, want := range map[string]os.FileMode{
		victim:                          0755,
		filepath.Join(victim, "nested"): 0755,
		secret:                          0644,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("lstat %s: %v", path, err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s is %v outside the state directory, want %v", path, info.Mode().Perm(), want)
		}
	}
	if target, err := os.Readlink(swapped); err != nil || target != victim {
		t.Fatalf("the replacement link changed: %q %v", target, err)
	}
}

// A unit the manager never read is not installed, whatever its bytes say. An
// install that cannot make the manager aware of it fails, and the next install
// tries again instead of skipping the reload because the bytes are unchanged.
func TestAFailedReloadIsRetriedByTheNextInstall(t *testing.T) {
	f := newFixture(t)
	f.manager.reloadErr = errors.New("the manager could not be reloaded")
	if _, err := f.install(demo.ExecutorSchema, "worker", true); !errors.Is(err, f.manager.reloadErr) {
		t.Fatalf("install with a failing reload: %v", err)
	}
	if state, _ := f.manager.State(context.Background(), UnitName(demo.ExecutorSchema, "worker")); state.Loaded {
		t.Fatalf("the unit was loaded after a failed reload: %+v", state)
	}
	f.manager.reloadErr = nil
	report, err := f.install(demo.ExecutorSchema, "worker", true)
	if err != nil {
		t.Fatalf("install after a failed reload: %v", err)
	}
	if !report.Ready {
		t.Fatalf("install after a failed reload: %+v", report)
	}
	state, err := f.manager.State(context.Background(), UnitName(demo.ExecutorSchema, "worker"))
	if err != nil || !state.Loaded || !state.Running() {
		t.Fatalf("unit state after the retry: %+v %v", state, err)
	}
}

// A managed dispatcher is started by the host at boot and is reachable on
// loopback by every account on that host, so the credential-free operator
// bypass must never be in its generated configuration. The configuration comes
// from the same generator the foreground roles use, and that generator serves
// an environment whose operator owns the whole machine, so the managed profile
// states the value itself instead of inheriting it.
func TestTheManagedDispatcherConfigurationNeverEnablesLocalDevelopment(t *testing.T) {
	f := newFixture(t)
	if _, err := f.install(demo.DispatcherSchema, "local", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(StateDirectory(f.root, demo.DispatcherSchema, "local"), "service.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Server struct {
			LocalDevelopment *bool `toml:"local_development"`
		} `toml:"server"`
	}
	if err := toml.Unmarshal(data, &generated); err != nil {
		t.Fatalf("read the generated configuration: %v", err)
	}
	if generated.Server.LocalDevelopment == nil {
		t.Fatalf("the generated configuration does not state local_development at all:\n%s", data)
	}
	if *generated.Server.LocalDevelopment {
		t.Fatalf("the generated configuration serves an unauthenticated caller as an operator:\n%s", data)
	}
}

// An installation that stopped before its database existed leaves the state
// directory it made and nothing in it. The next installation finishes the job
// rather than refusing forever, because the bootstrap can still run in a
// directory this administrator owns; it is the finished directory, handed to
// the service account, that no later installation can create anything in. A
// repeat over a finished installation rebuilds nothing either way.
func TestAnInterruptedInstallIsCompletedByTheNextOne(t *testing.T) {
	f := newFixture(t)
	if _, err := f.install(demo.ExecutorSchema, "worker", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	report, err := f.install(demo.ExecutorSchema, "worker", false)
	if err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if slices.Contains(report.Changed, "database") {
		t.Fatalf("a repeated install rebuilt the database: %+v", report.Changed)
	}
	// What an install interrupted between making the directory and finishing
	// the bootstrap leaves: the directory, without the database.
	stateDir := StateDirectory(f.root, demo.ExecutorSchema, "worker")
	if err := os.Remove(demo.RoleDatabase(stateDir, demo.ExecutorSchema)); err != nil {
		t.Fatal(err)
	}
	completed, err := f.install(demo.ExecutorSchema, "worker", false)
	if err != nil {
		t.Fatalf("an interrupted install can never be completed: %v", err)
	}
	if !slices.Contains(completed.Changed, "database") {
		t.Fatalf("the completing install does not report the database it made: %+v", completed.Changed)
	}
}

// A managed executor runs on a host that has other services on it, so the
// local environment's permission to measure against targets on that same
// machine must never reach its generated configuration: a debuglet would
// otherwise be able to reach whatever else the host serves on loopback and on
// the internal ranges.
func TestTheManagedExecutorConfigurationNeverPermitsLocalTargets(t *testing.T) {
	f := newFixture(t)
	if _, err := f.install(demo.ExecutorSchema, "worker", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(StateDirectory(f.root, demo.ExecutorSchema, "worker"), "service.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Network struct {
			Policy struct {
				LocalTargets *bool `toml:"local_targets"`
			} `toml:"policy"`
		} `toml:"network"`
	}
	if err := toml.Unmarshal(data, &generated); err != nil {
		t.Fatalf("read the generated configuration: %v", err)
	}
	if generated.Network.Policy.LocalTargets == nil {
		t.Fatalf("the generated configuration does not state local_targets at all:\n%s", data)
	}
	if *generated.Network.Policy.LocalTargets {
		t.Fatalf("the generated configuration permits measuring against this host's own services:\n%s", data)
	}
}

// A hard link is an ordinary regular file to whoever reads the directory: the
// name is this directory's, the file is not. The account owns this directory
// between installations and can make one, so a file this directory is not the
// only name for is refused rather than handed over with the rest.
func TestOwnershipRefusesASecondNameForAFileOutside(t *testing.T) {
	f := newFixture(t)
	installer, err := New(Options{
		Root: f.root, Manager: f.manager, ReadyTimeout: 2 * time.Second, StopTimeout: time.Second,
		// The real fchown and fchmod, with an account this test may apply.
		LookupAccount: func(string, string) (Account, error) {
			return Account{UID: os.Getuid(), GID: os.Getgid()}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.installer = installer
	if _, err := f.install(demo.ExecutorSchema, "worker", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	outside := filepath.Join(f.root, "outside")
	if err := os.WriteFile(outside, []byte("host file"), 0644); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(StateDirectory(f.root, demo.ExecutorSchema, "worker"), "linked")
	if err := os.Link(outside, linked); err != nil {
		t.Fatal(err)
	}

	report, err := f.install(demo.ExecutorSchema, "worker", false)
	if err == nil {
		t.Fatalf("a second name for a host file was handed to the service account: %+v", report)
	}
	if !strings.Contains(err.Error(), linked) {
		t.Fatalf("the refusal does not name the entry: %v", err)
	}
	info, err := os.Lstat(outside)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("the file behind the second name was changed: %v %v", info, err)
	}
}
