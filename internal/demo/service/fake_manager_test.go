package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/pelletier/go-toml/v2"
)

// fakeManager stands in for the host service manager. It is deliberately not a
// stub: it reads the unit this package generated, executes the daemon the unit
// names only in the sense that matters here, and publishes the readiness record
// from the configuration the installation wrote. A test therefore fails if the
// generated unit or the generated configuration is wrong, not only if the
// installer's own bookkeeping is.
type fakeManager struct {
	mu    sync.Mutex
	t     *testing.T
	root  string
	calls []string
	units map[string]*fakeUnit
	pid   int
	// silent daemons never publish a readiness record.
	silent bool
	// timedOut daemons are killed at the unit's stop timeout, which is what
	// a daemon that never finished its own shutdown looks like to the
	// manager: a failed unit with a timeout result.
	timedOut bool
	// stuck units never leave the deactivating state.
	stuck bool
	// reloadErr fails every reload while it is set, and with it every
	// attempt to make the manager aware of a newly written unit.
	reloadErr error
	// loaded records the units the manager has actually read.
	loaded map[string]bool
}

type fakeUnit struct {
	active, sub string
	enabled     bool
	pid         int
	result      string
	status      int
	ready       string
}

func newFakeManager(t *testing.T, root string) *fakeManager {
	return &fakeManager{t: t, root: root, units: map[string]*fakeUnit{}, loaded: map[string]bool{}, pid: 1000}
}

func (m *fakeManager) record(call string) {
	m.calls = append(m.calls, call)
}

// recorded returns every call this manager received, in order.
func (m *fakeManager) recorded() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.calls...)
}

func (m *fakeManager) Reload(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("reload")
	if m.reloadErr != nil {
		return m.reloadErr
	}
	// A reload is what makes written units known to the manager.
	entries, err := os.ReadDir(UnitDirectory(m.root))
	if err != nil {
		return err
	}
	m.loaded = map[string]bool{}
	for _, entry := range entries {
		m.loaded[entry.Name()] = true
	}
	return nil
}

func (m *fakeManager) Enable(_ context.Context, unit string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("enable " + unit)
	m.unit(unit).enabled = true
	return nil
}

func (m *fakeManager) Disable(_ context.Context, unit string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("disable " + unit)
	m.unit(unit).enabled = false
	return nil
}

func (m *fakeManager) Start(_ context.Context, unit string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("start " + unit)
	u := m.unit(unit)
	if u.active == "active" {
		return nil
	}
	config, ready, err := m.execStart(unit)
	if err != nil {
		return err
	}
	m.pid++
	u.active, u.sub, u.pid, u.ready = "active", "running", m.pid, ready
	u.result, u.status = "success", 0
	if m.silent {
		return nil
	}
	return m.publishReady(config, ready, u.pid)
}

func (m *fakeManager) Stop(_ context.Context, unit string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("stop " + unit)
	u := m.unit(unit)
	if m.stuck {
		u.active, u.sub = "deactivating", "stop-sigterm"
		return nil
	}
	// The runtime directory, and with it the readiness record, is removed
	// whenever the unit stops. That happens for a daemon that finished and
	// for one that was killed alike, which is why nothing here can be
	// concluded from the record being gone.
	if u.ready != "" {
		if err := os.RemoveAll(filepath.Dir(u.ready)); err != nil {
			return err
		}
	}
	u.pid = 0
	if m.timedOut {
		u.active, u.sub, u.result, u.status = "failed", "failed", "timeout", 9
		return nil
	}
	u.active, u.sub, u.result, u.status = "inactive", "dead", "success", 0
	return nil
}

func (m *fakeManager) State(_ context.Context, unit string) (UnitState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record("state " + unit)
	loaded := m.loaded[unit]
	if u, known := m.units[unit]; known && u.active == "failed" {
		// A failed unit keeps its failure until it is reset or run
		// again, even once its file is gone.
		return UnitState{Loaded: loaded, Active: u.active, Sub: u.sub, Enabled: u.enabled,
			Result: u.result, ExecMainStatus: u.status}, nil
	}
	if _, err := os.Stat(filepath.Join(UnitDirectory(m.root), unit)); err != nil {
		delete(m.units, unit)
		return UnitState{Active: "inactive", Sub: "dead", Result: "success"}, nil
	}
	if !loaded {
		// Written but never read by the manager, which is what a failed
		// reload, or none at all, leaves behind.
		return UnitState{Active: "inactive", Sub: "dead", Result: "success"}, nil
	}
	u := m.unit(unit)
	return UnitState{Loaded: true, Active: u.active, Sub: u.sub, Enabled: u.enabled,
		MainPID: u.pid, Result: u.result, ExecMainStatus: u.status}, nil
}

func (m *fakeManager) unit(name string) *fakeUnit {
	u, ok := m.units[name]
	if !ok {
		// A unit the manager has never run reports a successful result.
		u = &fakeUnit{active: "inactive", sub: "dead", result: "success"}
		m.units[name] = u
	}
	return u
}

// execStart reads the generated unit exactly as a service manager would: the
// daemon's arguments come from the unit file, not from the test.
func (m *fakeManager) execStart(unit string) (config, ready string, err error) {
	data, err := os.ReadFile(filepath.Join(UnitDirectory(m.root), unit))
	if err != nil {
		return "", "", err
	}
	for line := range strings.Lines(string(data)) {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "ExecStart=") {
			continue
		}
		for i, field := range fields {
			if i+1 >= len(fields) {
				break
			}
			switch field {
			case "-config", "--config":
				config = fields[i+1]
			case "-ready-file", "--ready-file":
				ready = fields[i+1]
			}
		}
	}
	if config == "" || ready == "" {
		return "", "", fmt.Errorf("unit %s has no complete ExecStart", unit)
	}
	return config, ready, nil
}

// publishReady writes the record the daemon publishes once it is actually
// ready, from the identity and ports of the configuration it was given.
func (m *fakeManager) publishReady(config, ready string, pid int) error {
	data, err := os.ReadFile(config)
	if err != nil {
		return err
	}
	var parsed struct {
		Identity struct {
			ExecutorID string `toml:"executor_id"`
		} `toml:"identity"`
		Server struct {
			HTTPPort int `toml:"http_port"`
			GRPCPort int `toml:"grpc_port"`
		} `toml:"server"`
		Database struct {
			Path string `toml:"path"`
		} `toml:"database"`
	}
	if err := toml.Unmarshal(data, &parsed); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ready), 0700); err != nil {
		return err
	}
	record := readiness.Record{SchemaVersion: 1, PID: pid}
	if parsed.Identity.ExecutorID != "" {
		record.ExecutorID = parsed.Identity.ExecutorID
	} else {
		record.HTTPAddr = fmt.Sprintf("127.0.0.1:%d", parsed.Server.HTTPPort)
		record.GRPCAddr = fmt.Sprintf("127.0.0.1:%d", parsed.Server.GRPCPort)
	}
	return readiness.Write(ready, record)
}
